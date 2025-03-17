import { Component, OnInit } from '@angular/core'; // Add OnInit here
import { AuthService, User } from '../../services/auth.service';
import { Router } from '@angular/router';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-profile',
  templateUrl: './profile.component.html',
  styleUrls: ['./profile.component.css'],
  imports: [CommonModule],
  standalone: true
})
export class ProfileComponent implements OnInit { // Add "implements OnInit" here
  user: User | null;
  isTwoFactorEnabled: boolean = false;
  error: string = '';

  constructor(
    private authService: AuthService,
    private router: Router
  ) {
    this.user = this.authService.currentUserValue;
  }

  ngOnInit(): void {
    this.authService.getTwoFactorStatus().subscribe({
      next: (data) => {
        this.isTwoFactorEnabled = data.isTwoFactorEnabled;
      },
      error: (err) => {
        this.error = err.error.message || 'Failed to fetch 2FA status.';
      },
    });
  }

  navigateToActivate2FA(): void {
    this.router.navigate(['/activate-2fa']);
  }

  navigateToResetPassword(): void {
    this.router.navigate(['/request-password-reset']);
  }

  logout(): void {
    this.authService.logout().subscribe({
      next: () => {
        // No need for console logs or extra steps
        // AuthService should handle redirection and cleanup
      },
      error: () => {
        this.error = 'Failed to logout. Please try again.';
      }
    });
  }
}
