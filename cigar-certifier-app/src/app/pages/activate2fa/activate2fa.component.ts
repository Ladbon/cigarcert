// File: src/app/pages/activate2fa/activate2fa.component.ts
import { Component } from '@angular/core';
import { AuthService } from '../../services/auth.service';
import { catchError, of } from 'rxjs';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router'; // Import RouterModule
import { Router } from '@angular/router'; // Import Router

@Component({
  selector: 'app-activate2fa',
  standalone: true,
  templateUrl: './activate2fa.component.html',
  styleUrls: ['./activate2fa.component.css'],
  imports: [CommonModule, FormsModule, RouterModule]
})
export class Activate2faComponent {
  qrCode: string = '';
  secretKey: string = '';
  verificationCode: string = '';
  error: string = '';
  message: string = '';

  constructor(private authService: AuthService, private router: Router) {
    this.get2FASetup();
  }

  get2FASetup(): void {
    this.authService.setupTwoFactor().pipe(
      catchError((error) => {
        this.error = error.error.message || 'Failed to initiate 2FA setup.';
        return of();
      })
    ).subscribe((data) => {
      this.qrCode = data.qrCode;
      this.secretKey = data.secretKey;
    });
  }

  onActivate2FA(): void {
    this.authService.activate2FA(this.verificationCode).subscribe({
      next: () => {
        this.message = 'Two-Factor Authentication activated successfully.';
        // Update 2FA status in profile
        this.authService.getTwoFactorStatus().subscribe(status => {
          this.authService.updateTwoFactorStatus(status.isTwoFactorEnabled);
          // Navigate back to profile after updating status
          this.router.navigate(['/profile']);
        });
      },
      error: (error) => {
        console.error('Error:', error);
        this.error = error.error.message || 'Failed to activate 2FA.';
      }
    });
  }


}

