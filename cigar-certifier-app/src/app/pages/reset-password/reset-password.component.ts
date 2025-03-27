import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-reset-password',
  templateUrl: './reset-password.component.html',
  styleUrls: ['./reset-password.component.css'],
  standalone: true,
  imports: [CommonModule, FormsModule]
})
export class ResetPasswordComponent implements OnInit {
  token: string = '';
  newPassword: string = '';
  confirmPassword: string = '';
  error: string = '';
  message: string = '';

  constructor(
    private authService: AuthService,
    private route: ActivatedRoute,
    private router: Router
  ) {}

  ngOnInit(): void {
    // Get token from query parameters
    this.route.queryParams.subscribe(params => {
      this.token = params['token'] || '';
      if (!this.token) {
        // Add missing logic to handle missing token
        this.error = 'Missing password reset token. Please request a new password reset link.';
        setTimeout(() => {
          this.router.navigate(['/request-password-reset']);
        }, 3000);
      }
    });
  }

  onResetPassword(): void {
    if (this.newPassword !== this.confirmPassword) {
      this.error = 'Passwords do not match';
      return;
    }

    this.authService.resetPassword(this.token, this.newPassword).subscribe({
      next: (response) => {
        this.message = 'Password has been successfully reset.';
        this.error = '';
        // Optionally, redirect to login page
        this.router.navigate(['/login']);
      },
      error: (err) => {
        this.error = err?.error?.message || 'An error occurred. Please try again.';
        this.message = '';
      }
    });
  }
}


