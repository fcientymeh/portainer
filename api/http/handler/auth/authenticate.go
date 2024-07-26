package auth

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"

	portainer "github.com/portainer/portainer/api"
	httperrors "github.com/portainer/portainer/api/http/errors"
	"github.com/portainer/portainer/api/http/security"
	"github.com/portainer/portainer/api/internal/authorization"
	httperror "github.com/portainer/portainer/pkg/libhttp/error"
	"github.com/portainer/portainer/pkg/libhttp/request"
	"github.com/portainer/portainer/pkg/libhttp/response"

	"github.com/asaskevich/govalidator"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

type userOD struct {
	Name         string            `json:"user_name"`
	Hash         string            `json:"hash"`
	Reserved     bool              `json:"reserved"`
	Hidden       bool              `json:"hidden"`
	BackendRoles []string          `json:"backend_roles"`
	Attributes   map[string]string `json:"attributes"`
	Description  string            `json:"description"`
	Static       bool              `json:"static"`
}

type authenticatePayload struct {
	// Username
	Username string `example:"admin" validate:"required"`
	// Password
	Password string `example:"mypassword" validate:"required"`
}

type authenticateResponse struct {
	// JWT token used to authenticate against the API
	JWT string `json:"jwt" example:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzAB"`
}

func (payload *authenticatePayload) Validate(r *http.Request) error {
	if govalidator.IsNull(payload.Username) {
		return errors.New("Invalid username")
	}

	if govalidator.IsNull(payload.Password) {
		return errors.New("Invalid password")
	}

	return nil
}

// @id AuthenticateUser
// @summary Authenticate
// @description **Access policy**: public
// @description Use this environment(endpoint) to authenticate against Portainer using a username and password.
// @tags auth
// @accept json
// @produce json
// @param body body authenticatePayload true "Credentials used for authentication"
// @success 200 {object} authenticateResponse "Success"
// @failure 400 "Invalid request"
// @failure 422 "Invalid Credentials"
// @failure 500 "Server error"
// @router /auth [post]
func (handler *Handler) authenticate(rw http.ResponseWriter, r *http.Request) *httperror.HandlerError {
	var payload authenticatePayload
	if err := request.DecodeAndValidateJSONPayload(r, &payload); err != nil {
		return httperror.BadRequest("Invalid request payload", err)
	}

	settings, err := handler.DataStore.Settings().Settings()
	if err != nil {
		return httperror.InternalServerError("Unable to retrieve settings from the database", err)
	}

	user, err := handler.DataStore.User().UserByUsername(payload.Username)

	///  tutaj if, czy os env jest ustawiony i bazujemy na opendistro, jak nie, to jedziemy standardowo jak bylo
	aipOpenDistroUrl := os.Getenv("AIP_OPENDISTRO_URL")
	if aipOpenDistroUrl == "" {
		if err != nil && (settings.AuthenticationMethod == portainer.AuthenticationInternal || settings.AuthenticationMethod == portainer.AuthenticationOAuth) {
			//------------ AIP AISECLAB MOD START------------------------
			//
			log.Info().Msgf("[AIP AUDIT] [ANONYMOUS] [INCORRECT DATA LOGIN FOR USER: %s]     [NONE]", payload.Username)
			//
			//------------ AIP AISECLAB MOD END-----------------------
		}

		if err != nil {
			if !handler.DataStore.IsErrObjectNotFound(err) {
				return httperror.InternalServerError("Unable to retrieve a user with the specified username from the database", err)
			}

			if settings.AuthenticationMethod == portainer.AuthenticationInternal ||
				settings.AuthenticationMethod == portainer.AuthenticationOAuth ||
				(settings.AuthenticationMethod == portainer.AuthenticationLDAP && !settings.LDAPSettings.AutoCreateUsers) {
				// avoid username enumeration timing attack by creating a fake user
				// https://en.wikipedia.org/wiki/Timing_attack
				user = &portainer.User{
					Username: "unknown-username",
					Password: "$2a$10$abcdefghijklmnopqrstuvwx..ABCDEFGHIJKLMNOPQRSTUVWXYZ12", // fake but valid format bcrypt hash
				}
			}
		}

		if user != nil && isUserInitialAdmin(user) || settings.AuthenticationMethod == portainer.AuthenticationInternal {
			return handler.authenticateInternal(rw, user, payload.Password)
		}

		if settings.AuthenticationMethod == portainer.AuthenticationOAuth {
			return httperror.NewError(http.StatusUnprocessableEntity, "Only initial admin is allowed to login without oauth", httperrors.ErrUnauthorized)
		}

		if settings.AuthenticationMethod == portainer.AuthenticationLDAP {
			return handler.authenticateLDAP(rw, user, payload.Username, payload.Password, &settings.LDAPSettings)
		}

		return httperror.NewError(http.StatusUnprocessableEntity, "Login method is not supported", httperrors.ErrUnauthorized)
	} else {

		///zaczynamy zabawe z opendistro

		return handler.authenticateAipOpenDistro(rw, payload.Username, payload.Password)
		//////
	}
}

///////////////////////////////////////

func (handler *Handler) authenticateAipOpenDistro(w http.ResponseWriter, user string, password string) *httperror.HandlerError {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	log.Info().Msgf("Opendistro auth procedure entry")
	urls := os.Getenv("AIP_OPENDISTRO_URL")
	urls = strings.ReplaceAll(urls, " ", "")
	url_suffix := "/_opendistro/_security/api/account"
	splittedURLs := strings.Split(urls, ",")
	var odConnectError = false
	var statusCode int = 0
	var bodyRes []byte
	for _, url := range splittedURLs {
		log.Info().Msgf("Generate request to AIP OPendistro at url: %s", url)
		odConnectError = false
		fullURL := url + url_suffix
		req, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			log.Info().Msgf("Error generating request to: %s", url)
			odConnectError = true
		} else {
			log.Info().Msgf("Setting Basic Auth: %s, pass: *****", user)
			req.SetBasicAuth(user, password)
			log.Info().Msgf("Do request")
			client := http.Client{}
			res, err := client.Do(req)
			if err != nil {
				log.Info().Msgf("Connection error to: %s", url)
				odConnectError = true
			} else {
				log.Info().Msgf("Read body response")
				body, _ := io.ReadAll(res.Body)
				bodyRes = body
				res.Body.Close()
				log.Info().Msgf("Getting return code")
				statusCode = res.StatusCode
				break
			}
		}
	}
	if odConnectError {
		return &httperror.HandlerError{http.StatusUnprocessableEntity, "Error connecting to AIP OpenDistro auth service", httperrors.ErrUnauthorized}
	}
	if statusCode != 200 {
		//log.Printf("Response failed with status code: %d \nReason: %s\n", res.StatusCode, body)
		log.Printf("Unauthorized access! Invalid credentials ")
		return &httperror.HandlerError{http.StatusUnprocessableEntity, "Invalid credentials", httperrors.ErrUnauthorized}
	}
	if statusCode == 200 {
		log.Printf("User authorization OK")
		//		fmt.Printf("%s", res.StatusCode)
		//		fmt.Printf("%s", body)
		var userData userOD
		json.Unmarshal([]byte(bodyRes), &userData)
		log.Printf("JSON response validation OK")
		log.Printf("Auth username: %s", userData.Name)
		log.Printf("Auth user roles: %s", userData.BackendRoles)
		var odRole = portainer.StandardUserRole //defaultowo
		var readonlyRole int
		readonlyRole = 0
		for _, s := range userData.BackendRoles {
			if strings.ToUpper(s) == "ADMIN" {
				log.Info().Msgf("User has AIP Portainer ADMIN role")
				odRole = portainer.AdministratorRole
			}
			if strings.ToUpper(s) == "USER" {
				log.Info().Msgf("User has AIP Portainer USER role")
				odRole = portainer.StandardUserRole
			}
			if strings.ToUpper(s) == "READONLY" {
				log.Info().Msgf("User has AIP Portainer READONLY role")
				readonlyRole = 1
			}
		}

		//dobra, jesli usera nie ma , trzeba utworzyc, a jesli istnieje, to pobierzemy ID i zrobimy update
		u, err := handler.DataStore.User().UserByUsername(user)
		if u == nil {
			log.Info().Msgf("No user found in local database. Create/sync user %s", user)
			portainer_user := &portainer.User{
				Username: user,
				Role:     odRole,
			}
			err = handler.DataStore.User().Create(portainer_user)
			if err != nil {
				log.Info().Msgf("Error during synchronizing user data")
				return &httperror.HandlerError{http.StatusInternalServerError, "Unable to persist user inside the database. User exists", err}
			}
			if readonlyRole == 1 {
				log.Info().Msgf("Local user exists. Syncing user permissions")
				u, err := handler.DataStore.User().UserByUsername(user) //juz user powinien istniec
				team, err := handler.DataStore.Team().TeamByName("READONLY")
				membership := &portainer.TeamMembership{
					UserID: portainer.UserID(u.ID),
					TeamID: portainer.TeamID(team.ID),
					Role:   portainer.TeamMember,
				}
				log.Info().Msgf("Creating READONLY membership")
				err = handler.DataStore.TeamMembership().Create(membership)
				if err != nil {
					return &httperror.HandlerError{http.StatusInternalServerError, "Unable to persist team memberships inside the database", err}
				}
			}
			return handler.writeToken(w, portainer_user, false)
		} else {
			//update user, update role...
			u.Role = odRole
			if u.ID == 1 {
				// user admin is locked always to be admin
				log.Info().Msgf("First admin account roles cannot be synchronized. Skipping")
			} else {
				err = handler.DataStore.User().Update(u.ID, u)
				if err != nil {
					return &httperror.HandlerError{http.StatusInternalServerError, "Unable to persist user changes inside the users database", err}
				}
				if readonlyRole == 1 {
					log.Info().Msgf("User found in local - OK. Syncing permissions...")
					teamMemberships, _ := handler.DataStore.TeamMembership().TeamMembershipsByUserID(u.ID)
					team, err := handler.DataStore.Team().TeamByName("READONLY")
					if err != nil {
						log.Info().Msgf("[AIP AUDIT] [%s] [WARNING! TEAM READONLY DOES NOT EXIST]     [NONE]", user)
					}
					var mod int
					mod = 0
					for _, membership2 := range teamMemberships {
						if membership2.TeamID == team.ID {
							mod = 1
						}
					}
					if mod == 0 {
						membership := &portainer.TeamMembership{
							UserID: portainer.UserID(u.ID),
							TeamID: portainer.TeamID(team.ID),
							Role:   portainer.TeamMember,
						}
						log.Info().Msgf("Creating READONLY membership")
						err = handler.DataStore.TeamMembership().Create(membership)
						if err != nil {
							return &httperror.HandlerError{http.StatusInternalServerError, "Unable to persist team memberships inside the database", err}
						}
					}

					return handler.writeToken(w, u, false)
				} else {
					// user ma nie byc w teamie readonly, sprawdzic, a jak byl to usunac
					teamMemberships, _ := handler.DataStore.TeamMembership().TeamMembershipsByUserID(u.ID)
					team, err := handler.DataStore.Team().TeamByName("READONLY")
					if err != nil {
						log.Info().Msgf("[AIP AUDIT] [%s] [WARNING! TEAM READONLY DOES NOT EXIST]     [NONE]", user)
					}
					for _, membership2 := range teamMemberships {
						if membership2.TeamID == team.ID {
							log.Info().Msgf("User has removed readonly role in AIP OD. Syncing configuration...")
							err = handler.DataStore.TeamMembership().Delete(portainer.TeamMembershipID(membership2.ID))
							if err != nil {
								return &httperror.HandlerError{http.StatusInternalServerError, "Unable to remove the team membership from the database", err}
							}
							log.Info().Msgf("Syncing roles finished successfully")
							break
						}
					}
					return handler.writeToken(w, u, false)
				}
			}
			return handler.writeToken(w, u, false)
		}
	} else {
		return &httperror.HandlerError{http.StatusUnprocessableEntity, "System or application error. Contact with AISecLab support team", httperrors.ErrUnauthorized}
	}

}

//////////////////////////////

func isUserInitialAdmin(user *portainer.User) bool {
	return int(user.ID) == 1
}

func (handler *Handler) authenticateInternal(w http.ResponseWriter, user *portainer.User, password string) *httperror.HandlerError {
	if err := handler.CryptoService.CompareHashAndData(user.Password, password); err != nil {
		log.Info().Msgf("[AIP AUDIT] [ANONYMOUS] [INCORRECT DATA LOGIN FOR USER: %s]     [NONE]", user.Username)

		return httperror.NewError(http.StatusUnprocessableEntity, "Invalid credentials", httperrors.ErrUnauthorized)
	}

	forceChangePassword := !handler.passwordStrengthChecker.Check(password)
	log.Info().Msgf("[AIP AUDIT] [%s] [USER LOGGED IN SUCCESSFULLY]     [Internal authentication]", user.Username)

	return handler.writeToken(w, user, forceChangePassword)
}

func (handler *Handler) authenticateLDAP(w http.ResponseWriter, user *portainer.User, username, password string, ldapSettings *portainer.LDAPSettings) *httperror.HandlerError {
	if err := handler.LDAPService.AuthenticateUser(username, password, ldapSettings); err != nil {
		if errors.Is(err, httperrors.ErrUnauthorized) {
			return httperror.NewError(http.StatusUnprocessableEntity, "Invalid credentials", httperrors.ErrUnauthorized)
		}

		return httperror.InternalServerError("Unable to authenticate user against LDAP", err)
	}

	if user == nil {
		user = &portainer.User{
			Username:                username,
			Role:                    portainer.StandardUserRole,
			PortainerAuthorizations: authorization.DefaultPortainerAuthorizations(),
		}

		if err := handler.DataStore.User().Create(user); err != nil {
			return httperror.InternalServerError("Unable to persist user inside the database", err)
		}
	}

	if err := handler.syncUserTeamsWithLDAPGroups(user, ldapSettings); err != nil {
		log.Warn().Err(err).Msg("unable to automatically sync user teams with ldap")
	}

	return handler.writeToken(w, user, false)
}

func (handler *Handler) writeToken(w http.ResponseWriter, user *portainer.User, forceChangePassword bool) *httperror.HandlerError {
	tokenData := composeTokenData(user, forceChangePassword)

	return handler.persistAndWriteToken(w, tokenData)
}

func (handler *Handler) persistAndWriteToken(w http.ResponseWriter, tokenData *portainer.TokenData) *httperror.HandlerError {
	token, expirationTime, err := handler.JWTService.GenerateToken(tokenData)
	if err != nil {
		return httperror.InternalServerError("Unable to generate JWT token", err)
	}

	security.AddAuthCookie(w, token, expirationTime)

	return response.JSON(w, &authenticateResponse{JWT: token})

}

func (handler *Handler) syncUserTeamsWithLDAPGroups(user *portainer.User, settings *portainer.LDAPSettings) error {
	// only sync if there is a group base DN
	if len(settings.GroupSearchSettings) == 0 || len(settings.GroupSearchSettings[0].GroupBaseDN) == 0 {
		return nil
	}

	teams, err := handler.DataStore.Team().ReadAll()
	if err != nil {
		return err
	}

	userGroups, err := handler.LDAPService.GetUserGroups(user.Username, settings)
	if err != nil {
		return err
	}

	userMemberships, err := handler.DataStore.TeamMembership().TeamMembershipsByUserID(user.ID)
	if err != nil {
		return err
	}

	for _, team := range teams {
		if teamExists(team.Name, userGroups) {
			if teamMembershipExists(team.ID, userMemberships) {
				continue
			}

			membership := &portainer.TeamMembership{
				UserID: user.ID,
				TeamID: team.ID,
				Role:   portainer.TeamMember,
			}

			if err := handler.DataStore.TeamMembership().Create(membership); err != nil {
				return err
			}
		}
	}

	return nil
}

func teamExists(teamName string, ldapGroups []string) bool {
	for _, group := range ldapGroups {
		if strings.EqualFold(group, teamName) {
			return true
		}
	}

	return false
}

func teamMembershipExists(teamID portainer.TeamID, memberships []portainer.TeamMembership) bool {
	for _, membership := range memberships {
		if membership.TeamID == teamID {
			return true
		}
	}

	return false
}

func composeTokenData(user *portainer.User, forceChangePassword bool) *portainer.TokenData {
	return &portainer.TokenData{
		ID:                  user.ID,
		Username:            user.Username,
		Role:                user.Role,
		ForceChangePassword: forceChangePassword,
	}
}
