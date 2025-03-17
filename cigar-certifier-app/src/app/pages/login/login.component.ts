import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { AuthService } from '../../services/auth.service';
import { LoginResponseDto } from '../../interfaces/login-response-interface';

@Component({
  selector: 'app-login',
  standalone: true,
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css'],
  imports: [CommonModule, FormsModule],
})
export class LoginComponent {
  username: string = '';
  password: string = '';
  twoFactorToken: string = '';
  error: string = '';
  requireTwoFactor: boolean = false;

  constructor(private authService: AuthService, private router: Router) { }

  navigateToResetPassword(): void {
    this.router.navigate(['/request-password-reset']);
  }

  navigateToSignUp(): void {
    this.router.navigate(['/register']);
  }

  onLogin() {
    this.error = ''; // Clear previous errors

    if (!this.username || !this.password) {
      this.error = 'Username and password must be provided';
      return;
    }

    // Prepare the login payload
    const loginPayload = {
      username: this.username,
      password: this.password,
      twoFactorToken: this.requireTwoFactor ? this.twoFactorToken : undefined,
    };

    this.authService.login(loginPayload).subscribe({
      next: (response) => {
        console.log('Login response:', response);
    
        if (response.isTwoFactorRequired) {
          this.requireTwoFactor = true;
          this.error = 'Please enter your verification code';
        } else {
          this.router.navigate(['/profile']);
        }
      },
      error: (err) => {
        console.error('Login error:', err);
        this.error = err.message;
        
        // Handle 2FA required case
        if (err.type === '2fa_required') {
          this.requireTwoFactor = true;
          // Optional: clear the error message since we're showing the 2FA input
          this.error = 'Please enter your verification code';
        } else if (err.type === 'invalid_2fa_token') {
          this.twoFactorToken = '';
        } else if (err.type === 'invalid_credentials') {
          // Optionally clear username/password fields
           this.password = '';
        }
      }
    });
  }

  logout(): void {
    this.authService.logout().subscribe({
      next: () => {
        // Nothing to do here - auth service handles everything
      },
      error: () => {
        // Nothing to do here - auth service handles everything
      }
    });
  }
}