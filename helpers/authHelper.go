package helpers

import(
	"fmt"
	"errors"
	"github.com/gin-gonic/gin"
)

func CheckUserType(c *gin.Context,role string)(err error){
	userType := c.GetString("user_type")
	err = nil
	if userType != role {
		err = errors.New("Unauthorized to access this resource")
		return err
	}
	return err
}

/* func MatchUserTypeToUid(c *gin.Context,userId string)(err error){
	userType := c.GetString("user_type")
	uid := c.GetString("uid")
	err = nil

	if userType == "USER" && uid != userId {
		err =  errors.New("Unauthorized to access this resource")
		return err
	}
	err = CheckUserType(c, userType)
	return err
} */

func MatchUserTypeToUid(c *gin.Context, userId string) error {
	// Query the database to check if there is a user with the given userId and user type 'user'
	fmt.Sprintf("userId : ",userId)

	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE user_id = $1 AND user_type = 'ADMIN'", userId).Scan(&count)
	if err != nil {
		return err // Return the error if any error occurred during the query
	}

	// If count is 0, it means there is no such user with the given userId and user type 'user'
	if count == 0 {
		return errors.New("user not found or user type mismatch") // Return an error indicating the mismatch
	}

	return nil // Return nil if the user with the given userId and user type 'user' is found
}

