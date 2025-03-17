import { Routes } from '@angular/router';
import { LoginComponent } from './pages/login/login.component';
import { RegisterComponent } from './pages/register/register.component';
import { ProfileComponent } from './pages/profile/profile.component';
import { ResetPasswordComponent } from './pages/reset-password/reset-password.component';
import { Activate2faComponent } from './pages/activate2fa/activate2fa.component';
import { RequestPasswordResetComponent } from './pages/request-password-reset/request-password-reset.component';
import { AuthGuard } from './guards/app.guard';

export const routes: Routes = [
  {
    path: '',
    component: LoginComponent
  },
  {
    path: 'register',
    component: RegisterComponent
  },
  {
    path: 'profile',
    component: ProfileComponent,
    canActivate: [AuthGuard],
  },
  {
    path: 'reset-password',
    component: ResetPasswordComponent,
  },
  {
    path: 'activate-2fa',
    component: Activate2faComponent,
    canActivate: [AuthGuard],
  },
  { path: 'request-password-reset', component: RequestPasswordResetComponent },
  { 
    path: '**', redirectTo: '' 
  }
];
