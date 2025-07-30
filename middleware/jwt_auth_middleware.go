package middleware

import (
	"TMS/initializers"
	"TMS/models"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// JWTAuthMiddleware validates JWT tokens and checks blacklist
func JWTAuthMiddleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header is required",
			})
			c.Abort()
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header must start with Bearer",
			})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Token is required",
			})
			c.Abort()
			return
		}

		// Check if token is blacklisted
		if isTokenBlacklisted(tokenString) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Token has been revoked",
			})
			c.Abort()
			return
		}

		// Parse and validate token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(os.Getenv("SECRET")), nil
		})

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token",
			})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// Check if token is expired
			if exp, ok := claims["exp"].(float64); ok {
				if time.Now().Unix() > int64(exp) {
					c.JSON(http.StatusUnauthorized, gin.H{
						"error": "Token has expired",
					})
					c.Abort()
					return
				}
			}

			// Check if it's an access token
			if tokenType, ok := claims["type"].(string); !ok || tokenType != "access" {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": "Invalid token type",
				})
				c.Abort()
				return
			}

			// Set user information in context
			c.Set("user_id", claims["user_id"])
			c.Set("email", claims["email"])
			c.Set("first_name", claims["first_name"])
			c.Set("last_name", claims["last_name"])
			c.Set("role", claims["role"])

			c.Next()
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token claims",
			})
			c.Abort()
			return
		}
	})
}

// RequireRole checks if the user has one of the required roles
func RequireRole(allowedRoles ...string) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		userRole, exists := c.Get("role")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Role information not found in token",
			})
			c.Abort()
			return
		}

		roleStr, ok := userRole.(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid role format",
			})
			c.Abort()
			return
		}

		// Check if user has any of the allowed roles
		for _, allowedRole := range allowedRoles {
			if roleStr == allowedRole {
				c.Next()
				return
			}
		}

		c.JSON(http.StatusForbidden, gin.H{
			"error": "Access denied. Insufficient permissions",
		})
		c.Abort()
	})
}

// isTokenBlacklisted checks if a token is in the blacklist
func isTokenBlacklisted(token string) bool {
	tokenHash := hashTokenForBlacklist(token)

	var blacklistedToken models.BlacklistedToken
	result := initializers.DB.Where("token_hash = ? AND expires_at > ?", tokenHash, time.Now()).First(&blacklistedToken)

	return result.Error == nil
}

// hashTokenForBlacklist creates a SHA256 hash of the token
func hashTokenForBlacklist(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
