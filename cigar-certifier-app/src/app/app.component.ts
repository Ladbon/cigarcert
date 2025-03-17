// app.component.ts
import { Component, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterOutlet } from '@angular/router';
import { AuthService } from './services/auth.service';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-root',
  standalone: true,
  templateUrl: './app.component.html',
  styleUrl: './app.component.css',
  imports: [CommonModule, RouterOutlet]
  })
export class AppComponent implements OnDestroy {
  title = 'CigarCertifier';
  showIdleWarning: boolean = false;
  idleWarningSubscription: Subscription;

  constructor(private authService: AuthService) {
    this.idleWarningSubscription = this.authService.idleWarning$.subscribe(() => {
      this.showIdleWarning = true;
    });
  }

  extendSession(): void {
    this.authService.extendSession();
    this.showIdleWarning = false;
  }

  logout(): void {
    this.authService.logout().subscribe({
      next: () => {
        // Handle successful logout if needed
      },
      error: (error) => {
        console.error('Logout error:', error);
      }
    });
  }

  ngOnDestroy(): void {
    if (this.idleWarningSubscription) {
      this.idleWarningSubscription.unsubscribe();
    }
  }
}
