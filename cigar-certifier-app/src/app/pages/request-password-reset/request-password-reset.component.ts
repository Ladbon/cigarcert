// request-password-reset.component.ts
import { Component } from '@angular/core';
import { AuthService } from '../../services/auth.service';
import { Router } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-request-password-reset',
  templateUrl: './request-password-reset.component.html',
  styleUrls: ['./request-password-reset.component.css'],
  standalone: true,
  imports: [CommonModule, FormsModule]
})
export class RequestPasswordResetComponent {
  email: string = '';
  error: string = '';
  message: string = '';
  isSubmitted: boolean = false;
  isSubmitting: boolean = false;

  constructor(private authService: AuthService, private router: Router) {}

  navigateToLogin(): void {
    this.router.navigate(['/']);
  }

  onRequestReset(): void {
    if (this.isSubmitting || this.isSubmitted) {
      return; // Prevent submission if already submitted or submitting
    }

    if (!this.email) {
      this.error = 'Email is required';
      return;
    }

    this.isSubmitting = true;
    this.authService.requestPasswordReset(this.email).subscribe({
      next: (response) => {
        this.message = response.message || 'If the email exists, password reset instructions have been sent.';
        this.error = '';
        this.isSubmitted = true; // Mark as submitted on success
        this.isSubmitting = false;
              },
      error: (err) => {
        // Even on error, we want to treat this as a success for security
        // This prevents revealing if an email exists in the system
        this.message = 'If the email exists, password reset instructions have been sent.';
        this.error = '';
        this.isSubmitted = true; // Mark as submitted even on error
        this.isSubmitting = false;
        
      }
    });
  }
}
