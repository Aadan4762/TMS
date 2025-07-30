package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"TMS/initializers"
	migrate "TMS/migarte"
	"TMS/routes/auth"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func init() {
	gin.SetMode(gin.ReleaseMode)

	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file:", err)
	}

	// Connect to database
	initializers.ConnectDB()

	// Run migrations
	migrate.CreateDbTables()

	// Seed database (create super admin)
	initializers.SeedDatabase()
}

func main() {
	// Set up Gin router
	r := gin.Default()

	// CORS configuration
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))
	r.Use(gin.Recovery())

	// Database connection settings
	sqlDB, _ := initializers.DB.DB()
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetMaxIdleConns(50)
	sqlDB.SetConnMaxLifetime(time.Hour)
	sqlDB.SetConnMaxIdleTime(30 * time.Minute)

	// Set up routes
	auth.AuthRoutes(r)

	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8080"
	}

	// Handle server timeouts to mitigate slow connections
	server := &http.Server{
		Addr:              ":" + port,
		Handler:           r,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       10 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		MaxHeaderBytes:    4 << 20,
	}

	log.Printf("Server starting on port %s", port)
	log.Println("Super Admin credentials (if created):")
	log.Printf("Email: %s", getEnvOrDefault("SUPER_ADMIN_EMAIL", "superadmin@tms.com"))
	log.Printf("Password: %s", getEnvOrDefault("SUPER_ADMIN_PASSWORD", "SuperAdmin@123"))
	log.Println("Please change the default password after first login!")

	// Start the server
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %s\n", err)
	}
}

// Helper function to get environment variable with default value
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
