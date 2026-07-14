package api

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.zx2c4.com/wireguard/mgmt/config"
	"golang.zx2c4.com/wireguard/mgmt/peers"
	"golang.zx2c4.com/wireguard/mgmt/ratelimit"
	"golang.zx2c4.com/wireguard/mgmt/store"
)

type Server struct {
	cfg     *config.Config
	store   *store.Store
	peers   *peers.Manager
	limiter ratelimit.Limiter
	engine  *gin.Engine
}

func New(cfg *config.Config, st *store.Store, pm *peers.Manager, limiter ratelimit.Limiter) *Server {
	gin.SetMode(gin.ReleaseMode)
	s := &Server{
		cfg:     cfg,
		store:   st,
		peers:   pm,
		limiter: limiter,
		engine:  gin.New(),
	}
	s.engine.Use(gin.Recovery(), s.authMiddleware())
	s.registerRoutes()
	return s
}

func (s *Server) Run() error {
	return s.engine.Run(":" + itoa(s.cfg.APIPort))
}

func (s *Server) registerRoutes() {
	v1 := s.engine.Group("/api/v1")
	{
		v1.GET("/health", s.health)
		v1.POST("/users", s.createUser)
		v1.GET("/users", s.listUsers)
		v1.GET("/users/:id", s.getUser)
		v1.PATCH("/users/:id", s.updateUser)
		v1.DELETE("/users/:id", s.deleteUser)
		v1.GET("/users/:id/config", s.getUserConfig)
		v1.GET("/users/:id/stats", s.getUserStats)
	}
}

func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.cfg.APIKey == "" {
			c.Next()
			return
		}
		key := c.GetHeader("X-API-Key")
		if key == "" {
			key = c.Query("api_key")
		}
		if key != s.cfg.APIKey {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Next()
	}
}

func (s *Server) health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) createUser(c *gin.Context) {
	var input store.CreateUserInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if input.BandwidthMbps < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bandwidth_mbps must be >= 0"})
		return
	}

	keys, err := peers.GenerateKeyPair()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	user, err := s.store.Create(input, keys.PublicKey, keys.PrivateKey)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	if err := s.peers.AddPeer(user.PublicKey, user.AssignedIP); err != nil {
		_, _ = s.store.Delete(user.ID)
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to add wireguard peer: " + err.Error()})
		return
	}

	if err := s.limiter.Apply(user); err != nil {
		_ = s.peers.RemovePeer(user.PublicKey)
		_, _ = s.store.Delete(user.ID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to apply bandwidth limit: " + err.Error()})
		return
	}

	c.JSON(http.StatusCreated, s.toUserResponse(user))
}

func (s *Server) toUserResponse(user *store.User) store.UserResponse {
	privateKey, _ := peers.KeyHexToBase64(user.PrivateKey)
	if privateKey == "" {
		privateKey = user.PrivateKey
	}
	publicKey, _ := peers.KeyHexToBase64(user.PublicKey)
	if publicKey == "" {
		publicKey = user.PublicKey
	}

	return store.UserResponse{
		ID:            user.ID,
		Name:          user.Name,
		PublicKey:     publicKey,
		PrivateKey:    privateKey,
		AssignedIP:    user.AssignedIP,
		BandwidthMbps: user.BandwidthMbps,
		Enabled:       user.Enabled,
		Config:        s.buildUserConfig(user),
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     user.UpdatedAt,
	}
}

func (s *Server) buildUserConfig(user *store.User) string {
	return peers.BuildClientConfig(
		user.PrivateKey,
		user.AssignedIP,
		s.cfg.ServerPublicKey,
		s.cfg.ServerEndpoint,
		s.cfg.DNS,
		s.cfg.KeepaliveInterval,
	)
}

func (s *Server) toUserResponses(users []store.User) []store.UserResponse {
	out := make([]store.UserResponse, len(users))
	for i := range users {
		out[i] = s.toUserResponse(&users[i])
	}
	return out
}

func (s *Server) listUsers(c *gin.Context) {
	users, err := s.store.List()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if users == nil {
		users = []store.User{}
	}
	c.JSON(http.StatusOK, s.toUserResponses(users))
}

func (s *Server) getUser(c *gin.Context) {
	user, err := s.store.Get(c.Param("id"))
	if err != nil {
		s.handleStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, s.toUserResponse(user))
}

func (s *Server) updateUser(c *gin.Context) {
	var input store.UpdateUserInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if input.BandwidthMbps != nil && *input.BandwidthMbps < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bandwidth_mbps must be >= 0"})
		return
	}

	user, err := s.store.Update(c.Param("id"), input)
	if err != nil {
		s.handleStoreError(c, err)
		return
	}

	if input.BandwidthMbps != nil {
		if err := s.limiter.Update(user); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update bandwidth limit: " + err.Error()})
			return
		}
	}

	if input.Enabled != nil {
		if user.Enabled {
			if err := s.peers.AddPeer(user.PublicKey, user.AssignedIP); err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": "failed to enable peer: " + err.Error()})
				return
			}
			if err := s.limiter.Apply(user); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to apply bandwidth limit: " + err.Error()})
				return
			}
		} else {
			_ = s.limiter.Remove(user)
			if err := s.peers.RemovePeer(user.PublicKey); err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": "failed to disable peer: " + err.Error()})
				return
			}
		}
	}

	c.JSON(http.StatusOK, s.toUserResponse(user))
}

func (s *Server) deleteUser(c *gin.Context) {
	user, err := s.store.Delete(c.Param("id"))
	if err != nil {
		s.handleStoreError(c, err)
		return
	}

	_ = s.limiter.Remove(user)
	if err := s.peers.RemovePeer(user.PublicKey); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to remove wireguard peer: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"deleted": true, "id": user.ID})
}

func (s *Server) getUserConfig(c *gin.Context) {
	user, err := s.store.Get(c.Param("id"))
	if err != nil {
		s.handleStoreError(c, err)
		return
	}

	config := s.buildUserConfig(user)

	c.JSON(http.StatusOK, store.ClientConfig{
		Interface: s.cfg.Interface,
		Config:    config,
	})
}

func (s *Server) getUserStats(c *gin.Context) {
	user, err := s.store.Get(c.Param("id"))
	if err != nil {
		s.handleStoreError(c, err)
		return
	}

	stats, err := s.peers.PeerStats(user.PublicKey)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, store.UserStats{
		TxBytes:           stats.TxBytes,
		RxBytes:           stats.RxBytes,
		LastHandshakeSec:  stats.LastHandshakeSec,
		LastHandshakeNsec: stats.LastHandshakeNsec,
	})
}

func (s *Server) handleStoreError(c *gin.Context, err error) {
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
