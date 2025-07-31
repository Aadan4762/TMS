package controller

import (
	"TMS/initializers"
	"TMS/models"
	"TMS/utils"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/microcosm-cc/bluemonday"
	"gorm.io/gorm"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var validate = validator.New()

type AuthController struct{}

// Register handles user registration
func (ac *AuthController) Register(ctx *gin.Context) {
	var user models.User

	if err := ctx.ShouldBindJSON(&user); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request data",
			"details": err.Error(),
		})
		return
	}

	// Validate input using struct tags
	if err := validate.Struct(&user); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Validation failed",
			"details": err.Error(),
		})
		return
	}

	// Custom validation: Check if password and confirm_password match
	if user.Password != user.ConfirmPassword {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Password and confirm password do not match",
		})
		return
	}

	// Additional password strength validation (optional)
	if len(user.Password) < 8 {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Password must be at least 8 characters long",
		})
		return
	}

	// Check if user already exists
	var existingUser models.User
	if err := initializers.DB.Where("email = ?", user.Email).First(&existingUser).Error; err == nil {
		ctx.JSON(http.StatusConflict, gin.H{
			"error": "User with this email already exists",
		})
		return
	}

	// Hash password before saving
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to hash password",
		})
		return
	}
	user.Password = string(hashedPassword)

	// Clear confirm_password before saving (it's not saved anyway due to gorm:"-")
	user.ConfirmPassword = ""

	// Create user
	if err := initializers.DB.Create(&user).Error; err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to create user",
			"details": err.Error(),
		})
		return
	}

	// Generate and send OTP
	otpCode := generateOTP()
	otp := models.OTPCode{
		Email:     user.Email,
		Code:      otpCode,
		Purpose:   "register",
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}

	if err := initializers.DB.Create(&otp).Error; err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate OTP",
		})
		return
	}

	// Send OTP via email
	go utils.SendOTPEmail(user.Email, user.FirstName, otpCode, "registration")

	ctx.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully. Please check your email for verification code.",
		"user_id": user.ID,
	})
}

// HardDeleteUser handles permanent user deletion (only super_admin can delete users)
func (ac *AuthController) HardDeleteUser(c *gin.Context) {
	// Get current user's role from JWT token
	currentUserRole := c.GetString("role")
	currentUserEmail := c.GetString("email")

	// Only super_admin can delete users
	if currentUserRole != "super_admin" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Access denied. Only super administrators can delete users",
		})
		return
	}

	var request struct {
		Email string `json:"email" validate:"required,email"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data",
		})
		return
	}

	if err := validate.Struct(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Validation failed",
			"details": err.Error(),
		})
		return
	}

	// Prevent super admin from deleting themselves
	if currentUserEmail == request.Email {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "You cannot delete your own account",
		})
		return
	}

	// Check if target user exists by email
	var targetUser models.User
	if err := initializers.DB.Where("email = ?", request.Email).First(&targetUser).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User with this email not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Database error while searching for user",
		})
		return
	}

	// Store user info before deletion for response
	deletedUserInfo := gin.H{
		"id":         targetUser.ID,
		"email":      targetUser.Email,
		"first_name": targetUser.FirstName,
		"last_name":  targetUser.LastName,
		"role":       targetUser.Role,
	}

	// Start transaction for cleanup
	tx := initializers.DB.Begin()
	if tx.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to start transaction",
		})
		return
	}

	// Delete related OTP codes first (if any)
	if err := tx.Where("email = ?", request.Email).Delete(&models.OTPCode{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete related OTP codes",
		})
		return
	}

	// Hard delete the user (this will permanently remove the record)
	if err := tx.Unscoped().Delete(&targetUser).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete user",
		})
		return
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to complete deletion",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      "User permanently deleted successfully",
		"deleted_user": deletedUserInfo,
	})
}

// VerifyEmail handles email verification with OTP
func (ac *AuthController) VerifyEmail(c *gin.Context) {
	var request struct {
		Email string `json:"email" validate:"required,email"`
		Code  string `json:"code" validate:"required,len=6"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data",
		})
		return
	}

	if err := validate.Struct(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Validation failed",
			"details": err.Error(),
		})
		return
	}

	// Find and validate OTP
	var otp models.OTPCode
	if err := initializers.DB.Where("email = ? AND code = ? AND purpose = ? AND used = ? AND expires_at > ?",
		request.Email, request.Code, "register", false, time.Now()).First(&otp).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid or expired OTP code",
		})
		return
	}

	// Mark OTP as used
	otp.Used = true
	initializers.DB.Save(&otp)

	// Update user email verification status
	if err := initializers.DB.Model(&models.User{}).Where("email = ?", request.Email).
		Update("is_email_verified", true).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to verify email",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Email verified successfully",
	})
}

// RefreshToken handles token refresh
func (ac *AuthController) RefreshToken(c *gin.Context) {
	var request struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data",
		})
		return
	}

	// Parse refresh token
	token, err := jwt.Parse(request.RefreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("SECRET")), nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid refresh token",
		})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid token claims",
		})
		return
	}

	// Check if it's a refresh token
	if claims["type"] != "refresh" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid token type",
		})
		return
	}

	// Get user
	userID := claims["user_id"].(string)
	var user models.User
	if err := initializers.DB.Where("id = ?", userID).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not found",
		})
		return
	}

	// Generate new access token
	accessToken, _, err := generateTokens(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate token",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
	})
}

// Logout handles user logout (requires JWT middleware)
func (ac *AuthController) Logout(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Authorization header required",
		})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Parse token to get expiry
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid token",
		})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid token claims",
		})
		return
	}

	// Add token to blacklist
	exp := int64(claims["exp"].(float64))
	tokenHash := hashToken(tokenString)

	blacklistedToken := models.BlacklistedToken{
		TokenHash: tokenHash,
		ExpiresAt: time.Unix(exp, 0),
	}

	if err := initializers.DB.Create(&blacklistedToken).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to logout",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
	})
}

// ForgotPassword handles password reset request
func (ac *AuthController) ForgotPassword(c *gin.Context) {
	var request struct {
		Email string `json:"email" validate:"required,email"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data",
		})
		return
	}

	if err := validate.Struct(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Validation failed",
		})
		return
	}

	// Check if user exists
	var user models.User
	if err := initializers.DB.Where("email = ?", request.Email).First(&user).Error; err != nil {
		// Don't reveal if email exists or not
		c.JSON(http.StatusOK, gin.H{
			"message": "If the email exists, a reset code has been sent",
		})
		return
	}

	// Generate and send OTP
	otpCode := generateOTP()
	otp := models.OTPCode{
		Email:     user.Email,
		Code:      otpCode,
		Purpose:   "reset_password",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := initializers.DB.Create(&otp).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate reset code",
		})
		return
	}

	// Send OTP via email
	go utils.SendOTPEmail(user.Email, user.FirstName, otpCode, "reset_password")

	c.JSON(http.StatusOK, gin.H{
		"message": "If the email exists, a reset code has been sent",
	})
}

// ResetPassword handles password reset with OTP
func (ac *AuthController) ResetPassword(c *gin.Context) {
	var request struct {
		Email           string `json:"email" validate:"required,email"`
		Code            string `json:"code" validate:"required,len=6"`
		NewPassword     string `json:"new_password" validate:"required,min=6"`
		ConfirmPassword string `json:"confirm_password" validate:"required,eqfield=NewPassword"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data",
		})
		return
	}

	if err := validate.Struct(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Validation failed",
			"details": err.Error(),
		})
		return
	}

	// Find and validate OTP
	var otp models.OTPCode
	if err := initializers.DB.Where("email = ? AND code = ? AND purpose = ? AND used = ? AND expires_at > ?",
		request.Email, request.Code, "reset_password", false, time.Now()).First(&otp).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid or expired reset code",
		})
		return
	}

	// Mark OTP as used
	otp.Used = true
	initializers.DB.Save(&otp)

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to hash password",
		})
		return
	}

	// Update user password
	if err := initializers.DB.Model(&models.User{}).Where("email = ?", request.Email).
		Update("password", string(hashedPassword)).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to reset password",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password reset successfully",
	})
}

// Helper functions
func generateOTP() string {
	otp := ""
	for i := 0; i < 6; i++ {
		num, _ := rand.Int(rand.Reader, big.NewInt(10))
		otp += strconv.Itoa(int(num.Int64()))
	}
	return otp
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// AssignRole handles role assignment (only super_admin can assign roles)
func (ac *AuthController) AssignRole(c *gin.Context) {
	// Get current user's role from JWT token
	currentUserRole := c.GetString("role")

	// Only super_admin can assign roles
	if currentUserRole != "super_admin" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Access denied. Only super administrators can assign roles",
		})
		return
	}

	var request struct {
		Email string `json:"email" validate:"required,email"`
		Role  string `json:"role" validate:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data",
		})
		return
	}

	if err := validate.Struct(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Validation failed",
			"details": err.Error(),
		})
		return
	}

	// Validate role values
	validRoles := map[string]bool{
		"user":        true,
		"teacher":     true,
		"admin":       true,
		"super_admin": true,
		"trainer":     true,
		"ict":         true,
	}

	if !validRoles[request.Role] {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid role. Valid roles are: user, teacher, admin, super_admin",
		})
		return
	}

	// Check if target user exists by email
	var targetUser models.User
	if err := initializers.DB.Where("email = ?", request.Email).First(&targetUser).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User with this email not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Database error while searching for user",
		})
		return
	}

	// Update user role
	if err := initializers.DB.Model(&targetUser).Update("role", request.Role).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to assign role",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Role assigned successfully",
		"user": gin.H{
			"id":         targetUser.ID,
			"email":      targetUser.Email,
			"first_name": targetUser.FirstName,
			"last_name":  targetUser.LastName,
			"role":       request.Role,
		},
	})
}

// GetUsers handles listing users with their roles (admin and super_admin only)
func (ac *AuthController) GetUsers(c *gin.Context) {
	currentUserRole := c.GetString("role")

	// Only admin and super_admin can view user list
	if currentUserRole != "admin" && currentUserRole != "super_admin" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Access denied. Insufficient permissions",
		})
		return
	}

	var users []models.User
	if err := initializers.DB.Select("id, first_name, last_name, email, role, is_email_verified, profile_completed, created_at, citizenship, sex, phone, sne").Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve users",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"users": users,
	})
}

// Update the generateTokens function to include role
func generateTokens(user models.User) (string, string, error) {
	// Access token (15 minutes)
	accessClaims := jwt.MapClaims{
		"user_id":    user.ID.String(),
		"email":      user.Email,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
		"role":       user.Role,
		"type":       "access",
		"exp":        time.Now().Add(15 * time.Minute).Unix(),
		"iat":        time.Now().Unix(),
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		return "", "", err
	}

	// Refresh token (7 days) - no need to include role here
	refreshClaims := jwt.MapClaims{
		"user_id": user.ID.String(),
		"type":    "refresh",
		"exp":     time.Now().Add(7 * 24 * time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		return "", "", err
	}

	return accessTokenString, refreshTokenString, nil
}

// Update Login method to include role in response
func (ac *AuthController) Login(c *gin.Context) {
	var request struct {
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data",
		})
		return
	}

	if err := validate.Struct(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Validation failed",
		})
		return
	}

	// Find user by email
	var user models.User
	if err := initializers.DB.Where("email = ?", request.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid credentials",
		})
		return
	}

	// Check password
	if !user.CheckPassword(request.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid credentials",
		})
		return
	}

	// Check if email is verified
	if !user.IsEmailVerified {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Please verify your email before logging in",
		})
		return
	}

	// Generate tokens
	accessToken, refreshToken, err := generateTokens(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate tokens",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":       "Login successful",
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

// UpdateProfile handles profile updates (requires JWT middleware)
func (ac *AuthController) UpdateProfile(c *gin.Context) {
	userID := c.GetString("user_id")

	var user models.User

	err := c.BindJSON(&user)
	if err != nil {
		c.JSON(400, gin.H{"message": "Re-validate the keyed in data and try again!"})
		return
	}

	// Validate citizenship
	validCitizenship := map[string]bool{
		"kenyan":     true,
		"non-kenyan": true,
		"":           true,
	}

	if !validCitizenship[strings.ToLower(user.Citizenship)] {
		c.JSON(400, gin.H{"message": "Citizenship must be either kenyan or non-kenyan"})
		return
	}

	// Validate sex
	validSex := map[string]bool{
		"M": true,
		"F": true,
		"":  true,
	}

	if !validSex[strings.ToUpper(user.Sex)] {
		c.JSON(400, gin.H{"message": "Sex must be either M or F"})
		return
	}

	// SNE validation is not needed since it's a boolean field (true/false/null)

	// Validate designation based on citizenship
	if user.Citizenship != "" {
		citizenship := strings.ToLower(user.Citizenship)
		designation := strings.ToLower(user.Designation)

		if citizenship == "kenyan" {
			validDesignations := map[string]bool{
				"teacher": true,
				"police":  true,
				"":        true,
			}
			if user.Designation != "" && !validDesignations[designation] {
				c.JSON(400, gin.H{"message": "For Kenyan citizens, designation must be Teacher or Police"})
				return
			}

			// Validate teacher-specific fields
			if designation == "teacher" {
				if user.TSCNumber == "" {
					c.JSON(400, gin.H{"message": "TSC Number is required for teachers"})
					return
				}
				if user.SchoolCounty == "" || user.SchoolSubCounty == "" {
					c.JSON(400, gin.H{"message": "School County and Sub-County are required for teachers"})
					return
				}
			}
		} else if citizenship == "non-kenyan" {
			validDesignations := map[string]bool{
				"guest": true,
				"":      true,
			}
			if user.Designation != "" && !validDesignations[designation] {
				c.JSON(400, gin.H{"message": "For Non-Kenyan citizens, designation must be Guest"})
				return
			}

			// Validate guest-specific fields
			if designation == "guest" {
				if user.OrganizationName == "" {
					c.JSON(400, gin.H{"message": "Organization Name is required for guests"})
					return
				}
			}
		}
	}

	// Validate ID/Passport number
	if user.Citizenship != "" {
		if strings.ToLower(user.Citizenship) == "kenyan" {
			if user.IDNumber == "" {
				c.JSON(400, gin.H{"message": "ID Number is required for Kenyan citizens"})
				return
			}
		} else if strings.ToLower(user.Citizenship) == "non-kenyan" {
			if user.PassportNumber == "" {
				c.JSON(400, gin.H{"message": "Passport Number is required for Non-Kenyan citizens"})
				return
			}
		}
	}

	// Validate phone number
	if user.Phone != "" && len(user.Phone) < 10 {
		c.JSON(400, gin.H{"message": "Phone number must be at least 10 digits"})
		return
	}

	// Create a policy for sanitization
	p := bluemonday.NewPolicy()

	// Prepare update map
	updateData := map[string]interface{}{
		"first_name":  p.Sanitize(user.FirstName),
		"last_name":   p.Sanitize(user.LastName),
		"phone":       p.Sanitize(user.Phone),
		"citizenship": p.Sanitize(strings.ToLower(user.Citizenship)),
		"sex":         p.Sanitize(strings.ToUpper(user.Sex)),
		"sne":         user.SNE, // No sanitization needed for boolean
		"designation": p.Sanitize(strings.ToLower(user.Designation)),
	}

	// Add citizenship-specific fields
	if strings.ToLower(user.Citizenship) == "kenyan" {
		updateData["id_number"] = p.Sanitize(user.IDNumber)
		updateData["passport_number"] = "" // Clear passport for Kenyan citizens

		// Add teacher-specific fields
		if strings.ToLower(user.Designation) == "teacher" {
			updateData["tsc_number"] = p.Sanitize(user.TSCNumber)
			updateData["school_county"] = p.Sanitize(user.SchoolCounty)
			updateData["school_sub_county"] = p.Sanitize(user.SchoolSubCounty)
			updateData["subjects_in_college"] = p.Sanitize(user.SubjectsInCollege)
			updateData["teaching_subjects"] = p.Sanitize(user.TeachingSubjects)
			updateData["organization_name"] = "" // Clear guest field
		} else {
			// Clear teacher fields if not a teacher
			updateData["tsc_number"] = ""
			updateData["school_county"] = ""
			updateData["school_sub_county"] = ""
			updateData["subjects_in_college"] = ""
			updateData["teaching_subjects"] = ""
			updateData["organization_name"] = ""
		}
	} else if strings.ToLower(user.Citizenship) == "non-kenyan" {
		updateData["passport_number"] = p.Sanitize(user.PassportNumber)
		updateData["id_number"] = "" // Clear ID number for Non-Kenyan citizens

		// Add guest-specific fields
		if strings.ToLower(user.Designation) == "guest" {
			updateData["organization_name"] = p.Sanitize(user.OrganizationName)
		} else {
			updateData["organization_name"] = ""
		}

		// Clear teacher fields for non-Kenyan citizens
		updateData["tsc_number"] = ""
		updateData["school_county"] = ""
		updateData["school_sub_county"] = ""
		updateData["subjects_in_college"] = ""
		updateData["teaching_subjects"] = ""
	}

	// Update user profile
	res := initializers.DB.Model(&user).Where("id = ?", userID).Updates(updateData)

	if res.Error != nil {
		c.JSON(400, gin.H{"message": "The server couldn't complete your request, please try again later!"})
		return
	}

	// Check number of rows affected
	if res.RowsAffected == 0 {
		c.JSON(400, gin.H{"message": "User with ID " + userID + " was not found!"})
		return
	}

	// Mark profile as completed if basic info is provided (check existing data)
	var currentUser models.User
	if err := initializers.DB.Where("id = ?", userID).First(&currentUser).Error; err == nil {
		// Check if basic info is complete (either from current data or update)
		firstName := currentUser.FirstName
		lastName := currentUser.LastName
		phone := currentUser.Phone
		citizenship := currentUser.Citizenship

		// Use updated values if provided
		if user.FirstName != "" {
			firstName = user.FirstName
		}
		if user.LastName != "" {
			lastName = user.LastName
		}
		if user.Phone != "" {
			phone = user.Phone
		}
		if user.Citizenship != "" {
			citizenship = user.Citizenship
		}

		if firstName != "" && lastName != "" && phone != "" && citizenship != "" {
			initializers.DB.Model(&models.User{}).Where("id = ?", userID).Update("profile_completed", true)
		}
	}

	// Get updated user data to return
	var updatedUser models.User
	if err := initializers.DB.Where("id = ?", userID).First(&updatedUser).Error; err != nil {
		c.JSON(400, gin.H{"message": "Failed to retrieve updated user data"})
		return
	}

	// Prepare response based on citizenship and designation
	response := gin.H{
		"id":                updatedUser.ID,
		"first_name":        updatedUser.FirstName,
		"last_name":         updatedUser.LastName,
		"email":             updatedUser.Email,
		"phone":             updatedUser.Phone,
		"citizenship":       updatedUser.Citizenship,
		"sex":               updatedUser.Sex,
		"sne":               updatedUser.SNE,
		"designation":       updatedUser.Designation,
		"profile_completed": updatedUser.ProfileCompleted,
	}

	// Add citizenship-specific fields to response
	if strings.ToLower(updatedUser.Citizenship) == "kenyan" {
		response["id_number"] = updatedUser.IDNumber

		if strings.ToLower(updatedUser.Designation) == "teacher" {
			response["tsc_number"] = updatedUser.TSCNumber
			response["school_county"] = updatedUser.SchoolCounty
			response["school_sub_county"] = updatedUser.SchoolSubCounty
			response["subjects_in_college"] = updatedUser.SubjectsInCollege
			response["teaching_subjects"] = updatedUser.TeachingSubjects
		}
	} else if strings.ToLower(updatedUser.Citizenship) == "non-kenyan" {
		response["passport_number"] = updatedUser.PassportNumber

		if strings.ToLower(updatedUser.Designation) == "guest" {
			response["organization_name"] = updatedUser.OrganizationName
		}
	}

	c.JSON(200, gin.H{
		"message": "Successfully saved the user's profile data.",
		"user":    response,
	})
}

func (ac *AuthController) GetProfile(c *gin.Context) {
	userID := c.GetString("user_id")

	var user models.User
	if err := initializers.DB.Where("id = ?", userID).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"id":         user.ID,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
			"email":      user.Email,
			"phone":      user.Phone,
			//"gender":            user.Gender,
			"role":              user.Role,
			"citizenship":       user.Citizenship,
			"sex":               user.Sex,
			"sne":               user.SNE,
			"is_email_verified": user.IsEmailVerified,
			"profile_completed": user.ProfileCompleted,
			"created_at":        user.CreatedAt,
		},
	})
}
