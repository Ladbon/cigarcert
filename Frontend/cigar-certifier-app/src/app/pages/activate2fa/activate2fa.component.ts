import { Component } from '@angular/core';
import { AuthService } from '../../services/auth.service';
import { catchError, of } from 'rxjs';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-activate2fa',
  standalone: true,
  templateUrl: './activate2fa.component.html',
  styleUrls: ['./activate2fa.component.css'],
  imports: [CommonModule, FormsModule]
})
export class Activate2faComponent {
  qrCodeUrl: string = '';
  secretKey: string = '';
  verificationCode: string = '';
  error: string = '';
  message: string = '';

  constructor(private authService: AuthService) {
    this.get2FASetup();
  }

  get2FASetup(): void {
    this.authService.get2FASetup().pipe(
      catchError((error) => {
        this.error = error.error.message || 'Failed to initiate 2FA setup.';
        return of();
      })
    ).subscribe((data) => {
      this.qrCodeUrl = data.qrCodeUrl;
      this.secretKey = data.secretKey;
    });
  }

  onActivate2FA(): void {
    this.authService.activate2FA(this.verificationCode).pipe(
      catchError((error) => {
        this.error = error.error.message || 'Failed to activate 2FA.';
        return of();
      })
    ).subscribe(() => {
      this.message = 'Two-Factor Authentication activated successfully.';
    });
  }
}
