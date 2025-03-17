import { Injectable } from '@angular/core';
import { HttpInterceptor, HttpRequest, HttpHandler, HttpEvent } from '@angular/common/http';
import { Observable } from 'rxjs';
import { AuthService } from '../services/auth.service';
import { publicEndpoints } from '../../environments/environment';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  // Define public endpoints that do not require authentication
  private publicEndpoints = publicEndpoints;

  constructor(private authService: AuthService) { }

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    // Add security headers and withCredentials to all requests
    // withCredentials ensures cookies are sent with cross-origin requests
    let secureReq = req.clone({
      withCredentials: true,
      setHeaders: {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block'
      }
    });
    
    // With HttpOnly cookies, we don't need to manually add an Authorization header
    // The browser automatically includes the auth cookie with requests

    return next.handle(secureReq);
  }
}
