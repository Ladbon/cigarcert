import { Component } from '@angular/core';
import { AuthService } from '../../services/auth.service';
import { catchError } from 'rxjs/operators';
import { of } from 'rxjs';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-reset-password',
  standalone: true,
  templateUrl: './reset-password.component.html',
  styleUrls: ['./reset-password.component.css'],
  imports: [CommonModule, FormsModule]
})
export class ResetPasswordComponent {
  currentPassword: string = '';
  newPassword: string = '';
  confirmPassword: string = '';
  error: string = '';
  message: string = '';

  constructor(private authService: AuthService) { }

  onResetPassword(): void {
    if (this.newPassword !== this.confirmPassword) {
      this.error = "New passwords don't match.";
      return;
    }

    this.authService.resetPassword(this.currentPassword, this.newPassword).pipe(
      catchError((error) => {
        this.error = error.error.message || 'Password reset failed.';
        return of(null);
      })
    ).subscribe(() => {
      this.message = 'Password has been reset successfully.';
    });
  }
}
