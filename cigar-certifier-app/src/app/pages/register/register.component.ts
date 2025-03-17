// register.component.ts
import { Component, OnDestroy } from '@angular/core';
import { AuthService } from '../../services/auth.service';
import { Router } from '@angular/router';
import { catchError, finalize, tap } from 'rxjs/operators';
import { of, timer } from 'rxjs';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { DomSanitizer } from '@angular/platform-browser';

interface ValidationErrors {
  [key: string]: string[];
}

@Component({
  selector: 'app-register',
  standalone: true,
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css'],
  imports: [CommonModule, FormsModule],
})
export class RegisterComponent implements OnDestroy {
  username: string = '';
  email: string = '';
  password: string = '';
  confirmationCode: string = '';
  error: string = '';
  message: string = '';
  showConfirmationField: boolean = false;

  // Timer properties
  timerValue: number = 900; // 15 minutes in seconds
  timer$: any;
  resendDisabled: boolean = false;
  resendTimerValue: number = 900; // 15 minutes in seconds
  resendTimer$: any;
  registrationComplete: boolean = false; 


  constructor(private authService: AuthService, private router: Router, private sanitizer: DomSanitizer) { }

  navigateToLogin(): void {
    this.router.navigate(['/login']);
  }

  validateInput(input: string): string {
    // Basic sanitization - strip HTML tags
    return input.replace(/<[^>]*>/g, '');
  }

  private isValidUsername(username: string): boolean {
    // Match backend validation exactly
    return /^[a-zA-Z0-9]{4,20}$/.test(username);
  }
  
  private isValidEmail(email: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }
  
  validatePassword(password: string): { isValid: boolean, message: string } {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChars = /[^\w\s]/.test(password);
        
    if (password.length < minLength) {
      return { isValid: false, message: `Password must be at least ${minLength} characters.` };
    }
    
    const requirements = [];
    if (!hasUpperCase) requirements.push('uppercase letter');
    if (!hasLowerCase) requirements.push('lowercase letter');
    if (!hasNumbers) requirements.push('number');
    if (!hasSpecialChars) requirements.push('special character');
    
    if (requirements.length > 0) {
      return { 
        isValid: false, 
        message: `Password must include at least one ${requirements.join(', ')}.` 
      };
    }
    
    return { isValid: true, message: '' };
  }

  onRegister(): void {
    this.message = '';
    this.error = '';
    
    // Check username
    if (!this.username) {
      this.error = "Username is required";
      return;
    }
    
    if (this.username.length < 4 || this.username.length > 20) {
      this.error = `Username must be between 4 and 20 characters (current: ${this.username.length})`;
      return;
    }
    
    if (!/^[a-zA-Z0-9]+$/.test(this.username)) {
      this.error = "Username can only contain letters and numbers (no spaces or special characters)";
      return;
    }
    
    // Check email
    if (!this.email) {
      this.error = "Email is required";
      return;
    }
    
    if (!this.isValidEmail(this.email)) {
      this.error = "Please enter a valid email address";
      return;
    }

    const passwordCheck = this.validatePassword(this.password);
    if (!passwordCheck.isValid) {
      this.error = passwordCheck.message;
      return;
    }

    this.authService.register(this.username, this.email, this.password).pipe(
      tap((response: any) => {
        this.message = response.message || 'Registration successful! Please check your email for the confirmation code.';
        this.error = '';
        this.showConfirmationField = true;
        this.startTimer();
        this.startResendTimer();
      }),
      catchError((error) => this.handleError(error))
    ).subscribe();
  }

  onConfirmEmail(): void {
    this.message = '';
    this.error = '';

    this.authService.confirmEmail(this.email, this.confirmationCode).pipe(
      tap((response: any) => {
        this.message = 'Code confirmed and account created!';
        this.error = '';
        this.showConfirmationField = false;
        this.registrationComplete = true; // Show login button
      }),
      catchError((error) => this.handleError(error))
    ).subscribe();
  }

  onResendCode(): void {
    this.authService.resendConfirmationCode(this.email).pipe(
      tap((response: any) => {
        this.message = response.message || 'Confirmation code resent successfully! Please check your email, including your junk mail folder.';
        this.startResendTimer();
      }),
      catchError((error) => this.handleError(error))
    ).subscribe();
  }

  startTimer(): void {
    this.timerValue = 900; // Reset timer
    this.timer$ = timer(0, 1000).subscribe(() => {
      this.timerValue--;
      if (this.timerValue <= 0) {
        this.timer$.unsubscribe();
        this.error = 'Confirmation code has expired. Please request a new one.';
        this.showConfirmationField = false;
      }
    });
  }

  startResendTimer(): void {
    this.resendDisabled = true;
    this.resendTimerValue = 900; // Reset resend timer
    this.resendTimer$ = timer(0, 1000).subscribe(() => {
      this.resendTimerValue--;
      if (this.resendTimerValue <= 0) {
        this.resendTimer$.unsubscribe();
        this.resendDisabled = false;
      }
    });
  }

  handleError(error: any) {
    // Clear the success message when there is an error
    this.message = '';

    if (error.status === 400) {
      // Handle validation errors
      if (error.error?.errors) {
        const errors = error.error.errors as ValidationErrors;
        // Format the errors into a readable string
        this.error = Object.entries(errors)
          .map(([field, messages]) => {
            const fieldName = this.getFriendlyFieldName(field);
            return `${fieldName}: ${messages.join(' ')}`;
          })
          .join(' ');
      } else if (error.error?.message) {
        this.error = error.error.message;
      } else {
        this.error = 'An error occurred. Please check your input.';
      }
    } else if (error.status === 429) {
      this.error = error.error?.message || 'Too many requests. Please wait before trying again.';
      // Optionally, start the resend timer based on the Retry-After header
      const retryAfter = parseInt(error.headers.get('Retry-After'), 10);
      if (retryAfter && !isNaN(retryAfter)) {
        this.resendTimerValue = retryAfter;
        this.startResendTimer();
      }
    } else {
      this.error = 'An unexpected error occurred. Please try again later.';
    }
    return of(null); // Return observable for error handling
  }

  private getFriendlyFieldName(field: string): string {
    const fieldMap: { [key: string]: string } = {
      Username: 'Username',
      Email: 'Email',
      Password: 'Password',
      ConfirmationCode: 'Confirmation Code'
    };
    return fieldMap[field] || field;
  }

  get formattedTimer(): string {
    const minutes = Math.floor(this.timerValue / 60);
    const seconds = this.timerValue % 60;
    return `${this.padZero(minutes)}:${this.padZero(seconds)}`;
  }

  padZero(num: number): string {
    return num < 10 ? '0' + num : num.toString();
  }

  ngOnDestroy(): void {
    if (this.timer$) this.timer$.unsubscribe();
    if (this.resendTimer$) this.resendTimer$.unsubscribe();
  }

}
