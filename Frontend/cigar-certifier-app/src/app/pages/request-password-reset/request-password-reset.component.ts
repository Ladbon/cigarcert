import { Component } from '@angular/core';
import { AuthService } from '../../services/auth.service';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-request-password-reset',
  standalone: true,
  templateUrl: './request-password-reset.component.html',
  styleUrls: ['./request-password-reset.component.css'],
  imports: [CommonModule, FormsModule]
})
export class RequestPasswordResetComponent {
  usernameOrEmail: string = '';
  error: string = '';
  message: string = '';

  constructor(private authService: AuthService) { }

  onRequestReset(): void {
    this.authService.requestPasswordReset(this.usernameOrEmail).subscribe({
      next: () => {
        this.message = 'Password reset instructions have been sent to your email.';
      },
      error: (error) => {
        this.error = error.error.message || 'Failed to send password reset instructions.';
      }
    });
  }
}
