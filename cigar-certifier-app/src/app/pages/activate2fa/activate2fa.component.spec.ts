import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { Activate2faComponent } from './activate2fa.component';

describe('Activate2faComponent', () => {
  let component: Activate2faComponent;
  let fixture: ComponentFixture<Activate2faComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [Activate2faComponent],
      providers: [
        provideHttpClient(), // Add this
        provideHttpClientTesting() // Add this
      ]
    })
    .compileComponents();
    fixture = TestBed.createComponent(Activate2faComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
