package payload

type LoginRequest struct {
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type SignUpRequest struct {
	Email    string `json:"email"     validate:"required,email"`
	Password string `json:"password"  validate:"required"`
	FullName string `json:"full_name" validate:"required"`
}

type SignUpResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type LoginWithGoogleRequest struct {
	IDToken string `json:"id_token" validate:"required"`
}

type LoginWithGoogleResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type LoginWithFacebookRequest struct {
	AccessToken string `json:"access_token" validate:"required"`
}

type LoginWithFacebookResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type LoginWithAppleRequest struct {
	IdentityToken     string `json:"identity_token"     validate:"required"`
	AuthorizationCode string `json:"authorization_code"`
	UserIdentifier    string `json:"user_identifier"`
}

type LoginWithAppleResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
