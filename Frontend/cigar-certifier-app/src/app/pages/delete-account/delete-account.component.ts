import { Component } from '@angular/core';
import { AuthService } from '../../services/auth.service';
import { Router } from '@angular/router';
import { catchError, tap } from 'rxjs/operators';
import { of } from 'rxjs';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-delete-account',
  standalone: true,
  templateUrl: './delete-account.component.html',
  styleUrls: ['./delete-account.component.css'],
  imports: [CommonModule, FormsModule]
})
export class DeleteAccountComponent {
  currentPassword1: string = '';
  currentPassword2: string = '';
  twoFaEnabled: boolean = false;
  twoFaToken: string = '';
  error: string = '';
  message: string = '';

  constructor(private authService: AuthService, private router: Router) { }

  onDeleteAccount(): void {
    if (this.currentPassword1 !== this.currentPassword2) {
      this.error = "Passwords do not match.";
      return;
    }

    this.authService.deleteAccount(this.currentPassword1, this.twoFaToken).pipe(
      tap(() => {
        this.message = 'Your account has been deleted.';
        // Log the user out and navigate to login page
        this.authService.logout();
      }),
      catchError((error) => {
        this.error = error.error.message || 'Failed to delete account.';
        return of();
      })
    ).subscribe();
  }
}
