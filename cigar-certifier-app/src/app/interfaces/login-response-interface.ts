export interface LoginResponseDto {
    isTwoFactorRequired: boolean;
    token?: string;
    expiresAt?: string; // ISO string format
    message?: string;
  }
  