package ledger

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type Account struct {
	ID    uint
	Owner string
	Label string
}

type labelChange struct{ Label string }

func open(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var a Account
		if err := c.ShouldBindJSON(&a); err != nil {
			return
		}
		// ruleid: traust-go-mass-assignment-bind-and-save
		db.Create(&a)
	}
}

func replace(db *gorm.DB, w http.ResponseWriter, r *http.Request) {
	var a Account
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		return
	}
	// ruleid: traust-go-mass-assignment-bind-and-save
	db.Save(&a)
}

func relabel(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var in labelChange
		if err := c.ShouldBindJSON(&in); err != nil {
			return
		}
		var a Account
		db.First(&a, c.Param("id"))
		a.Label = in.Label
		// ok: traust-go-mass-assignment-bind-and-save
		db.Save(&a)
	}
}
