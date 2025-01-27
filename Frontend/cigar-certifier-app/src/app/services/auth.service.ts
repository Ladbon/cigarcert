import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, BehaviorSubject } from 'rxjs';
import { Router } from '@angular/router';

export interface User {
  username: string;
  email?: string;
}

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  private apiUrl = 'https://localhost:5000/api/auth'; // Replace with your API's base URL
  private currentUserSubject: BehaviorSubject<User | null>;
  public currentUser: Observable<User | null>;

  constructor(private http: HttpClient, private router: Router) {
    const storedUser = localStorage.getItem('currentUser');
    this.currentUserSubject = new BehaviorSubject<User | null>(
      storedUser ? JSON.parse(storedUser) : null
    );
    this.currentUser = this.currentUserSubject.asObservable();
  }

  public get currentUserValue(): User | null {
    return this.currentUserSubject.value;
  }

  public updateCurrentUser(user: User | null): void {
    this.currentUserSubject.next(user);
  }

  login(username: string, password: string): Observable<any> {
    return this.http.post<any>(`${this.apiUrl}/login`, { username, password });
  }

  register(username: string, email: string, password: string, enable2FA: boolean): Observable<any> {
    return this.http.post<any>(`${this.apiUrl}/register`, {
      username,
      email,
      password,
      enableTwoFactor: enable2FA,
    });
  }

  logout() {
    // Remove user data from local storage
    localStorage.removeItem('currentUser');
    localStorage.removeItem('token');
    this.updateCurrentUser(null);
    this.router.navigate(['/']);
  }

  resetPassword(currentPassword: string, newPassword: string): Observable<any> {
    const body = { currentPassword, newPassword };
    return this.http.post<any>(`${this.apiUrl}/reset-password`, body);
  }

  requestPasswordReset(usernameOrEmail: string): Observable<any> {
    const body = { usernameOrEmail };
    return this.http.post<any>(`${this.apiUrl}/request-password-reset`, body);
  }

  get2FASetup(): Observable<any> {
    return this.http.get<any>(`${this.apiUrl}/2fa/setup`);
  }

  activate2FA(verificationCode: string): Observable<any> {
    const body = { verificationCode };
    return this.http.post<any>(`${this.apiUrl}/2fa/activate`, body);
  }

  deleteAccount(password: string, verificationCode?: string): Observable<any> {
    const body = { password, verificationCode };
    return this.http.post<any>(`${this.apiUrl}/delete-account`, body);
  }
}
