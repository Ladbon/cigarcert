import { Component } from '@angular/core';
import { AuthService } from '../../services/auth.service';
import { Router } from '@angular/router';
import { catchError } from 'rxjs/operators';
import { of } from 'rxjs';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-register',
  standalone: true,
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css'],
  imports: [CommonModule, FormsModule]
})
export class RegisterComponent {
  username: string = '';
  email: string = '';
  password: string = '';
  enable2FA: boolean = false;
  error: string = '';
  message: string = '';

  constructor(private authService: AuthService, private router: Router) { }

  onRegister(): void {
    this.authService
      .register(this.username, this.email, this.password, this.enable2FA)
      .pipe(
        catchError((error) => {
          this.error = error.error.message || 'Registration failed';
          return of(null);
        })
      )
      .subscribe((response) => {
        if (response) {
          this.message = 'Registration successful! Please check your email to confirm your account.';
          // Optionally navigate to login page
          // this.router.navigate(['/']);
        }
      });
  }
}
