import { Component } from '@angular/core';
import { AuthService } from '../../services/auth.service';
import { Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-login',
  standalone: true,
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css'],
  imports: [CommonModule, FormsModule]
})
export class LoginComponent {
  username: string = '';
  password: string = '';
  error: string = '';

  constructor(private authService: AuthService, private router: Router) { }

  onLogin(): void {
    this.authService.login(this.username, this.password).subscribe(
      (data) => {
        // Assuming the API returns an object with a 'token' property
        localStorage.setItem('token', data.token);
        localStorage.setItem('currentUser', JSON.stringify({ username: this.username }));
        this.authService.updateCurrentUser({ username: this.username });
        this.router.navigate(['/profile']);
      },
      (error) => {
        this.error = error.error.message || 'Login failed';
      }
    );
  }
}
