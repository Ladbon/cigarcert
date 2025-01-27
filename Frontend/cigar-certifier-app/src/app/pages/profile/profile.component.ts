import { Component } from '@angular/core';
import { AuthService, User } from '../../services/auth.service';
import { Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-profile',
  standalone: true,
  templateUrl: './profile.component.html',
  styleUrls: ['./profile.component.css'],
})
export class ProfileComponent {
  user: User | null;
  passwordVisible: boolean = false;

  constructor(private authService: AuthService, private router: Router) {
    this.user = this.authService.currentUserValue;
  }

  togglePasswordVisibility(): void {
    this.passwordVisible = !this.passwordVisible;
  }

  logout(): void {
    this.authService.logout();
  }
}
