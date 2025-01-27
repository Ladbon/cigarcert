import { Component } from '@angular/core';
import { Router } from '@angular/router';

@Component({
  standalone: true,
  selector: 'app-login',
  templateUrl: './login.component.html'
})
export class LoginComponent {
  username = '';
  password = '';

  constructor(private router: Router) {}

  onLogin() {
    // Normally you'd call a service, then navigate if successful
    // For now, just navigate to the profile
    this.router.navigate(['/profile']);
  }
}