import { HttpClient } from '@angular/common/http';
import { Injectable, NgZone } from '@angular/core';
import { Router } from '@angular/router';
import { Observable, BehaviorSubject, of, throwError, Subject } from 'rxjs';
import { tap, catchError } from 'rxjs/operators';
import { environment } from '../../environments/environment';
import { LoginResponseDto } from '../interfaces/login-response-interface';

export interface LoginPayload {
  username: string;
  password: string;
  twoFactorToken?: string;
}

export interface User {
  username: string;
  email?: string;
}

export interface TwoFactorStatusResponse {
  isTwoFactorEnabled: boolean;
}

export interface TwoFactorSetupResponse {
  message: string;
  qrCode: string;
  secretKey: string;
}

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  private baseUrl = environment.apiUrl;
  private currentUserSubject: BehaviorSubject<User | null> = new BehaviorSubject<User | null>(null);
  public currentUser: Observable<User | null>;

  private loginAttempts = 0;
  private readonly MAX_LOGIN_ATTEMPTS = 5;
  private loginLockoutTimestamp: number | null = null;
  private readonly LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes
  private readonly IDLE_TIMEOUT = 30 * 60 * 1000; // 30 minutes
  private readonly WARNING_TIMEOUT = 2 * 60 * 1000; // 2 minutes before logout
  private idleTimer: any;
  private warningTimer: any;
  private idleWarningSubject: Subject<void> = new Subject<void>();
  public idleWarning$: Observable<void> = this.idleWarningSubject.asObservable();

  constructor(private http: HttpClient, private router: Router, private ngZone: NgZone) {
    this.currentUser = this.currentUserSubject.asObservable();
    const userData = localStorage.getItem('currentUser');
    if (userData) {
      this.currentUserSubject.next(JSON.parse(userData));
    }
    
    // Set up idle detection (once)
    this.setupIdleWatcher();
  }

  public get currentUserValue(): User | null {
    return this.currentUserSubject.value;
  }

  public updateCurrentUser(user: User | null): void {
    if (user) {
      localStorage.setItem('currentUser', JSON.stringify(user));
    } else {
      localStorage.removeItem('currentUser');
    }
    this.currentUserSubject.next(user);
  }

  // Remove duplicate event listeners
  private setupIdleWatcher(): void {
    this.ngZone.runOutsideAngular(() => {
      const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'];
      events.forEach(event => {
        document.addEventListener(event, () => this.resetIdleTimer());
      });
    });
    
    this.resetIdleTimer();
  }

  extendSession(): void {
    this.resetIdleTimer();
  }

  login(payload: LoginPayload): Observable<LoginResponseDto> {
    // Check for lockout
    if (this.loginLockoutTimestamp && Date.now() < this.loginLockoutTimestamp) {
      const timeLeft = Math.ceil((this.loginLockoutTimestamp - Date.now()) / 60000);
      return throwError(() => ({
        message: `Too many failed attempts. Please try again in ${timeLeft} minutes.`,
        type: 'account_locked'
      }));
    }

    return this.http.post<LoginResponseDto>(`${this.baseUrl}/login`, payload, { withCredentials: true })
    .pipe(
      tap(response => {
        // Reset attempts on success
        this.loginAttempts = 0;
        // Update user in localStorage if 2FA is not required
        if (!response.isTwoFactorRequired) {
          this.updateCurrentUser({ username: payload.username });
          
          // Start refresh timer if we have expiry
          if (response.expiresAt) {
            this.startRefreshTokenTimer(response.expiresAt);
          }
        }
      }),
      catchError(error => {
        // Increment attempts on failure
        if (error.status === 401) {
          this.loginAttempts++;
          if (this.loginAttempts >= this.MAX_LOGIN_ATTEMPTS) {
            this.loginLockoutTimestamp = Date.now() + this.LOCKOUT_DURATION;
            return throwError(() => ({
              message: 'Too many failed attempts. Your account is temporarily locked.',
              type: 'account_locked',
              originalError: error
            }));
          }
        }
        // Create a user-friendly error object
        let errorMessage: string;
        let errorType: string;

        if (error.status === 0) {
          // Network error (offline, server down, CORS issue)
          errorMessage = 'Cannot connect to the server. Please check your connection.';
          errorType = 'network_error';
        } else if (error.status === 401) {
          if (payload.twoFactorToken) {
            errorMessage = 'Invalid 2FA code. Please try again.';
            errorType = 'invalid_2fa_token';
          } else {
            errorMessage = 'Invalid username or password.';
            errorType = 'invalid_credentials';
          }
        } else if (error.status === 400) {
          // Only general validation errors now - not 2FA required
          errorMessage = error.error?.errorMessage || 'Invalid login request.';
          errorType = 'validation_error';
        } else {
          errorMessage = 'An unexpected error occurred. Please try again later.';
          errorType = 'server_error';
        }

        // Return a structured error
        return throwError(() => ({
          message: errorMessage,
          type: errorType,
          originalError: error
        }));
      })
    );
  }

  logout(): Observable<any> {
    return this.http.delete<any>(`${this.baseUrl}/logout`, { withCredentials: true })
      .pipe(
        tap(() => {
          this.cleanupSession();
          // Explicitly navigate to login after logout
          this.router.navigate(['/login']);
        }),
        catchError(error => {
          // Even if the server request fails, clean up local session
          this.cleanupSession();

          let errorMessage: string;
          let errorType: string;

          if (error.status === 0) {
            errorMessage = 'Cannot connect to the server.';
            errorType = 'network_error';
          } else {
            errorMessage = 'Logout failed. Local session cleared.';
            errorType = 'logout_error';
          }

          return of({
            success: false,
            message: errorMessage,
            type: errorType
          });
        })
      );
  }

  getTwoFactorStatus(): Observable<TwoFactorStatusResponse> {
    return this.http.get<TwoFactorStatusResponse>(`${this.baseUrl}/2fa-status`, { withCredentials: true });
  }

  setupTwoFactor(): Observable<TwoFactorSetupResponse> {
    return this.http.patch<TwoFactorSetupResponse>(`${this.baseUrl}/setup-2fa`, {}, { withCredentials: true });
  }

  register(username: string, email: string, password: string): Observable<any> {
    return this.http.post<any>(`${this.baseUrl}/register`, { username, email, password }, { withCredentials: true });
  }

  resetPassword(token: string, newPassword: string): Observable<any> {
    const body = { token, newPassword };
    return this.http.put<any>(`${this.baseUrl}/reset-password`, body, { withCredentials: true })
      .pipe(
        tap(() => {
          // Automatically navigate to login page after successful reset
          this.router.navigate(['/login'], { 
            queryParams: { message: 'Password reset successful. Please log in with your new password.' }
          });
        })
      );
  }

  requestPasswordReset(email: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/request-password-reset`, { email }, { withCredentials: true });
  }

  activate2FA(verificationCode: string): Observable<any> {
    const body = { verificationCode };
    return this.http.post<any>(`${this.baseUrl}/activate-2fa`, body, { withCredentials: true });
  }

  private twoFactorEnabledSubject: BehaviorSubject<boolean> = new BehaviorSubject<boolean>(false);
  public twoFactorEnabled$: Observable<boolean> = this.twoFactorEnabledSubject.asObservable();

  public updateTwoFactorStatus(isEnabled: boolean): void {
    this.twoFactorEnabledSubject.next(isEnabled);
  }

  confirmEmail(email: string, confirmationCode: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/confirm-email`, {
      email,
      confirmationCode,
    }, { withCredentials: true });
  }

  resendConfirmationCode(email: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/resend-confirmation-code`, email, { withCredentials: true });
  }

  private resetIdleTimer(): void {
    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
    }

    if (this.warningTimer) {
      clearTimeout(this.warningTimer);
    }

    // Start warning timer
    this.warningTimer = setTimeout(() => {
      this.idleWarningSubject.next();
    }, this.IDLE_TIMEOUT - this.WARNING_TIMEOUT);

    // Start logout timer
    this.idleTimer = setTimeout(() => {
      this.logout().subscribe();
    }, this.IDLE_TIMEOUT);
  }

  stopIdleTimer(): void {
    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
    }
    if (this.warningTimer) {
      clearTimeout(this.warningTimer);
    }
  }

  private cleanupSession(): void {
    this.stopRefreshTokenTimer();
    this.stopIdleTimer();
    this.updateCurrentUser(null);
    this.router.navigate(['/']);
  }

  private refreshTokenTimeout: any;

  private startRefreshTokenTimer(expiresAt: Date | string): void {
    this.stopRefreshTokenTimer();

    const expires = new Date(expiresAt).getTime();
    const timeout = expires - Date.now() - (60 * 1000); // Refresh 1 minute before expiry

    if (timeout <= 0) {
      return;
    }

    this.refreshTokenTimeout = setTimeout(() => {
      this.refreshToken().subscribe();
    }, timeout);
  }

  private stopRefreshTokenTimer(): void {
    if (this.refreshTokenTimeout) {
      clearTimeout(this.refreshTokenTimeout);
    }
  }

  refreshToken(): Observable<LoginResponseDto> {
    return this.http.post<LoginResponseDto>(`${this.baseUrl}/refresh-token`, {}, { withCredentials: true })
      .pipe(
        tap(response => {
          if (response.expiresAt) {
            this.startRefreshTokenTimer(response.expiresAt);
          }
        }),
        catchError(error => {
          this.logout().subscribe();
          return throwError(() => ({
            message: 'Session expired. Please log in again.',
            type: 'session_expired'
          }));
        })
      );
  }
}
