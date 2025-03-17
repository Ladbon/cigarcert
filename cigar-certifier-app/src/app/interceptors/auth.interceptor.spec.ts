import { TestBed } from '@angular/core/testing';
import { HTTP_INTERCEPTORS, HttpInterceptor } from '@angular/common/http';

import { AuthInterceptor } from './auth.interceptor';

describe('AuthInterceptor', () => {
  let interceptor: HttpInterceptor;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        { provide: HTTP_INTERCEPTORS, useClass: AuthInterceptor, multi: true }
      ]
    });

    interceptor = TestBed.inject(HTTP_INTERCEPTORS)[0] as HttpInterceptor;
  });

  it('should be created', () => {
    expect(interceptor).toBeTruthy();
  });
});
