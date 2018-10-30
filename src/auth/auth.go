package auth

import (
	"auth/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/jacoblai/httprouter"
	"net/http"
	"strings"
)

func (d *DbEngine) Auth(next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		auth := r.Header.Get("Authorization")
		if auth != "" && InjectionPass([]byte(auth)) && strings.HasPrefix(auth, "Bearer ") {
			token := strings.Replace(auth, "Bearer ", "", -1)
			rtoken, _ := jwt.ParseWithClaims(token, &models.CoolpyClaims{}, func(token *jwt.Token) (interface{}, error) {
				return d.SigningKey, nil
			})

			if tk, ok := rtoken.Claims.(*models.CoolpyClaims); ok && rtoken.Valid && tk.Issuer == "coolpy7_api" {
				r.Header.Del("uoid")
				r.Header.Set("uoid", tk.UserId.Hex())
				r.Header.Del("uid")
				r.Header.Set("uid", tk.Uid)
				r.Header.Del("rule")
				r.Header.Set("rule", tk.Rule)
				next(w, r, ps)
				return
			}
		}

		// Request Basic Authentication otherwise
		w.Header().Set("WWW-Authenticate", "Bearer realm=Restricted")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	}
}
