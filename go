package main

import (
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/crypto/bcrypt"
)

// Структура пользователя
type User struct {
	Name     string `json:"name" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// Структура для генерации токена
type jwtCustomClaims struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	jwt.StandardClaims
}

type CustomValidator struct {
	validator *validator.Validate
}

func (cv *CustomValidator) Validate(i interface{}) error {
	if err := cv.validator.Struct(i); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	return nil
}

// Функция для хеширования пароля
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// Функция для сравнения паролей
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func main() {
	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Validator = &CustomValidator{validator: validator.New()}

	secretKey := []byte("your_secret_key")

	// Обработчик регистрации
	e.POST("/register", func(c echo.Context) error {
		u := new(User)
		if err := c.Bind(u); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		if err := c.Validate(u); err != nil {
			return err
		}

		// Хеширование пароля
		hashedPassword, err := hashPassword(u.Password)
		if err != nil {
			return err
		}
		u.Password = hashedPassword

		return c.JSON(http.StatusCreated, u)
	})

	// Обработчик логина
	e.POST("/login", func(c echo.Context) error {
		u := new(User)
		if err := c.Bind(u); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		// Здесь вы должны получить пользователя из базы данных по email
		// и сравнить хэши паролей

		// Генерация токена
		claims := &jwtCustomClaims{
			u.Name,
			u.Email,
			jwt.StandardClaims{
				ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		t, err := token.SignedString(secretKey)
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, map[string]string{
			"token": t,
		})
	})

	// Защищенная группа маршрутов
	r := e.Group("/restricted")
	r.Use(middleware.JWTWithConfig(middleware.JWTConfig{
		SigningKey: secretKey,
	}))

	// Защищенный эндпоинт 1
	r.GET("/profile", func(c echo.Context) error {
		user := c.Get("user").(*jwt.Token)
		claims := user.Claims.(*jwtCustomClaims)
		return c.JSON(http.StatusOK, map[string]string{
			"message": "Доступ разрешен",
			"name":    claims.Name,
			"email":   claims.Email,
		})
	})

	// Защищенный эндпоинт 2
	r.GET("/data", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{
			"message": "Секретные данные",
		})
	})

	e.Logger.Fatal(e.Start(":1323"))
}
