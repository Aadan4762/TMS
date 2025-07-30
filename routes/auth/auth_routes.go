package auth

import (
	"TMS/controller"
	"TMS/middleware"

	"github.com/gin-gonic/gin"
)

func AuthRoutes(r *gin.Engine) {
	authController := &controller.AuthController{}

	// Public routes (no JWT required)
	r.POST("/api/auth/register", authController.Register)
	r.POST("/api/auth/verify-email", authController.VerifyEmail)
	r.POST("/api/auth/login", authController.Login)
	r.POST("/api/auth/forgot-password", authController.ForgotPassword)
	r.POST("/api/auth/reset-password", authController.ResetPassword)
	r.POST("/api/auth/refresh-token", authController.RefreshToken)

	// Protected routes with JWT middleware
	protected := r.Group("/api/v1")
	protected.Use(middleware.JWTAuthMiddleware())
	{
		// Routes accessible by all authenticated users
		protected.GET("/user/profile", authController.GetProfile)
		protected.PUT("/user/profile", authController.UpdateProfile)
		protected.POST("/user/logout", authController.Logout)

		// Admin routes with inline role middleware
		protected.GET("/admin/users", middleware.RequireRole("admin", "super_admin"), authController.GetUsers)
		protected.DELETE("/user/delete", middleware.RequireRole("super_admin"), authController.HardDeleteUser)

		// Super admin only routes
		protected.POST("/admin/assign-role", middleware.RequireRole("super_admin"), authController.AssignRole)
	}

}
