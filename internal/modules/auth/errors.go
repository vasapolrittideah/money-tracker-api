package auth

import "errors"

var (
	// Authentication errors
	ErrAccountNotFound      = errors.New("ไม่พบบัญชีผู้ใช้")
	ErrAccountAlreadyExists = errors.New("บัญชีนี้มีอยู่แล้ว")
	ErrInvalidCredentials   = errors.New("อีเมลหรือรหัสผ่านไม่ถูกต้อง")

	// Email verification errors
	ErrEmailVerificationNotFound = errors.New("ไม่พบการยืนยันอีเมล")
	ErrEmailVerificationExpired  = errors.New("รหัสยืนยันอีเมลหมดอายุ")
	ErrEmailVerificationUsed     = errors.New("รหัสยืนยันอีเมลถูกใช้งานแล้ว")
	ErrEmailVerificationInvalid  = errors.New("รหัสยืนยันอีเมลไม่ถูกต้อง")
)
