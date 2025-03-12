// Configuración global
const CONFIG = {
  SESSION_KEY: 'camello_user_session',
  TOKEN_KEY: 'camello_auth_token',
  LOGIN_ATTEMPTS_KEY: 'camello_login_attempts',
  MAX_LOGIN_ATTEMPTS: 5,
  LOCKOUT_TIME: 15 * 60 * 1000, // 15 minutos en milisegundos
  REDIRECT_URLS: {
      freelancer: 'freelancer-dashboard.html',
      company: 'company-dashboard.html',
      admin: 'admin-panel.html'
  },
  TOAST_DURATION: 3000
};

// Inicialización cuando el DOM está listo
document.addEventListener('DOMContentLoaded', () => {
  // Set current year in footer
  document.getElementById('current-year').textContent = new Date().getFullYear();
  
  // Inicializar componentes de la UI
  initializeUI();
  
  // Verificar si el usuario ya está logueado
  checkExistingSession();
  
  // Inicializar formularios
  initializeLoginForm();
  initializeRegisterForm();
});

// Inicialización de componentes de la UI
function initializeUI() {
  // Mobile menu toggle
  const mobileMenuButton = document.getElementById('mobile-menu-button');
  const mobileMenu = document.getElementById('mobile-menu');
  
  mobileMenuButton.addEventListener('click', () => {
      mobileMenu.classList.toggle('hidden');
  });
  
  // Login/Register tabs
  const tabLogin = document.getElementById('tab-login');
  const tabRegister = document.getElementById('tab-register');
  const contentLogin = document.getElementById('content-login');
  const contentRegister = document.getElementById('content-register');
  const switchToRegister = document.getElementById('switch-to-register');
  const switchToLogin = document.getElementById('switch-to-login');
  
  function showLogin() {
      tabLogin.classList.add('bg-camel-tan', 'text-camel-white');
      tabLogin.classList.remove('text-camel-black');
      tabRegister.classList.remove('bg-camel-tan', 'text-camel-white');
      tabRegister.classList.add('text-camel-black');
      contentLogin.classList.remove('hidden');
      contentRegister.classList.add('hidden');
  }
  
  function showRegister() {
      tabRegister.classList.add('bg-camel-tan', 'text-camel-white');
      tabRegister.classList.remove('text-camel-black');
      tabLogin.classList.remove('bg-camel-tan', 'text-camel-white');
      tabLogin.classList.add('text-camel-black');
      contentRegister.classList.remove('hidden');
      contentLogin.classList.add('hidden');
  }
  
  tabLogin.addEventListener('click', showLogin);
  tabRegister.addEventListener('click', showRegister);
  switchToRegister.addEventListener('click', showRegister);
  switchToLogin.addEventListener('click', showLogin);
  
  // Account type toggle
  const typeFreelancer = document.getElementById('type-freelancer');
  const typeCompany = document.getElementById('type-company');
  const freelancerFields = document.getElementById('freelancer-fields');
  const companyFields = document.getElementById('company-fields');
  
  typeFreelancer.addEventListener('change', () => {
      if (typeFreelancer.checked) {
          freelancerFields.classList.remove('hidden');
          companyFields.classList.add('hidden');
      }
  });
  
  typeCompany.addEventListener('change', () => {
      if (typeCompany.checked) {
          companyFields.classList.remove('hidden');
          freelancerFields.classList.add('hidden');
      }
  });
}

// Verificar si hay una sesión existente
function checkExistingSession() {
  if (sessionManager.isLoggedIn()) {
      const user = sessionManager.getUserSession();
      // Verificar si el token es válido
      if (sessionManager.validateToken()) {
          redirectUserByType(user.type);
      } else {
          // Si el token no es válido, limpiar la sesión
          sessionManager.clearUserSession();
          showToast('error', 'Tu sesión ha expirado. Por favor, inicia sesión nuevamente.');
      }
  }
}

// Inicializar formulario de login
function initializeLoginForm() {
  const loginForm = document.getElementById('login-form');
  
  loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      
      // Verificar si la cuenta está bloqueada
      if (isAccountLocked()) {
          const remainingTime = getRemainingLockoutTime();
          showToast('error', `Cuenta bloqueada. Intenta de nuevo en ${Math.ceil(remainingTime / 60000)} minutos.`);
          return;
      }
      
      const email = document.getElementById('login-email').value;
      const password = document.getElementById('login-password').value;
      const rememberMe = document.getElementById('remember-me').checked;
      
      // Validación básica
      if (!validateEmail(email)) {
          showToast('error', 'Por favor, ingresa un correo electrónico válido');
          return;
      }
      
      if (!password) {
          showToast('error', 'Por favor, ingresa tu contraseña');
          return;
      }
      
      // Mostrar indicador de carga
      toggleLoadingState(loginForm, true);
      
      try {
          const user = await authService.login(email, password);
          
          if (user) {
              // Login exitoso
              resetLoginAttempts();
              sessionManager.setUserSession(user, rememberMe);
              showToast('success', `Bienvenido de nuevo, ${user.firstName}!`);
              
              // Esperar antes de redirigir para que el usuario vea el mensaje
              setTimeout(() => {
                  redirectUserByType(user.type);
              }, 1000);
          } else {
              // Login fallido
              incrementLoginAttempts();
              showToast('error', 'Correo electrónico o contraseña incorrectos');
              
              // Verificar si se debe bloquear la cuenta
              if (getLoginAttempts() >= CONFIG.MAX_LOGIN_ATTEMPTS) {
                  lockAccount();
                  showToast('error', `Demasiados intentos fallidos. Cuenta bloqueada por ${CONFIG.LOCKOUT_TIME / 60000} minutos.`);
              } else {
                  const remainingAttempts = CONFIG.MAX_LOGIN_ATTEMPTS - getLoginAttempts();
                  showToast('error', `Te quedan ${remainingAttempts} intentos antes de que tu cuenta sea bloqueada.`);
              }
          }
      } catch (error) {
          console.error('Error durante el login:', error);
          showToast('error', 'Ha ocurrido un error. Por favor, inténtalo de nuevo.');
      } finally {
          // Ocultar indicador de carga
          toggleLoadingState(loginForm, false);
      }
  });
}

// Inicializar formulario de registro
function initializeRegisterForm() {
  const registerForm = document.getElementById('register-form');
  
  registerForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const firstName = document.getElementById('register-firstname').value;
      const lastName = document.getElementById('register-lastname').value;
      const email = document.getElementById('register-email').value;
      const password = document.getElementById('register-password').value;
      const accountType = document.querySelector('input[name="account-type"]:checked').value;
      const termsAccepted = document.getElementById('terms').checked;
      
      // Validación de campos
      if (!firstName || !lastName) {
          showToast('error', 'Por favor, completa todos los campos obligatorios');
          return;
      }
      
      if (!validateEmail(email)) {
          showToast('error', 'Por favor, ingresa un correo electrónico válido');
          return;
      }
      
      if (!validatePassword(password)) {
          showToast('error', 'La contraseña debe tener al menos 8 caracteres, una mayúscula y un número');
          return;
      }
      
      if (!termsAccepted) {
          showToast('error', 'Debes aceptar los términos y condiciones');
          return;
      }
      
      // Datos específicos según el tipo de cuenta
      let userData = {
          firstName,
          lastName,
          email,
          password,
          type: accountType
      };
      
      if (accountType === 'freelancer') {
          const username = document.getElementById('register-username').value;
          if (!username) {
              showToast('error', 'Por favor, ingresa un nombre de usuario');
              return;
          }
          userData.username = username;
      } else if (accountType === 'company') {
          const companyName = document.getElementById('register-company').value;
          if (!companyName) {
              showToast('error', 'Por favor, ingresa el nombre de la empresa');
              return;
          }
          userData.companyName = companyName;
      }
      
      // Mostrar indicador de carga
      toggleLoadingState(registerForm, true);
      
      try {
          const result = await authService.register(userData);
          
          if (result.success) {
              // Registro exitoso
              sessionManager.setUserSession(result.user, true);
              showToast('success', '¡Cuenta creada exitosamente!');
              
              // Simular envío de correo de verificación
              simulateEmailVerification(email);
              
              // Esperar antes de redirigir
              setTimeout(() => {
                  redirectUserByType(accountType);
              }, 1000);
          } else {
              showToast('error', result.error || 'Error al crear la cuenta');
          }
      } catch (error) {
          console.error('Error durante el registro:', error);
          showToast('error', 'Ha ocurrido un error. Por favor, inténtalo de nuevo.');
      } finally {
          // Ocultar indicador de carga
          toggleLoadingState(registerForm, false);
      }
  });
}

// Servicio de autenticación
const authService = {
  login: async function(email, password) {
      try {
          // Simular retraso de red
          await new Promise(resolve => setTimeout(resolve, 800));
          
          // En una aplicación real, esto haría una petición a un servidor
          const users = await this.getUsers();
          const user = users.find(u => u.email === email && u.password === password);
          
          if (user) {
              // Generar token de autenticación
              const token = this.generateToken(user);
              user.token = token;
              return user;
          }
          
          return null;
      } catch (error) {
          console.error("Error en login:", error);
          throw error;
      }
  },
  
  register: async function(userData) {
      try {
          // Simular retraso de red
          await new Promise(resolve => setTimeout(resolve, 1000));
          
          // Verificar si el correo ya existe
          const users = await this.getUsers();
          if (users.some(u => u.email === userData.email)) {
              return { 
                  success: false, 
                  error: "Este correo electrónico ya está registrado" 
              };
          }
          
          // En una aplicación real, esto enviaría los datos al servidor
          const newUser = {
              id: Math.floor(Math.random() * 1000) + 10,
              ...userData,
              token: this.generateToken(userData),
              verified: false,
              createdAt: new Date().toISOString()
          };
          
          return {
              success: true,
              user: newUser
          };
      } catch (error) {
          console.error("Error en registro:", error);
          throw error;
      }
  },
  
  getUsers: async function() {
      // En una aplicación real, esto obtendría los usuarios de una API
      return [
          {
              id: 1,
              type: "freelancer",
              email: "freelancer@camello.co",
              password: "Freelancer123",
              firstName: "Carlos",
              lastName: "Rodríguez",
              username: "carlosdev",
              verified: true
          },
          {
              id: 2,
              type: "company",
              email: "empresa@camello.co",
              password: "Empresa123",
              firstName: "Ana",
              lastName: "Gómez",
              companyName: "InnovaTech Colombia",
              verified: true
          },
          {
              id: 3,
              type: "admin",
              email: "admin@camello.co",
              password: "Admin123",
              firstName: "Javier",
              lastName: "Martínez",
              username: "admin_javier",
              verified: true
          }
      ];
  },
  
  generateToken: function(user) {
      // En una aplicación real, esto generaría un JWT
      const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
      const payload = btoa(JSON.stringify({
          sub: user.id,
          name: `${user.firstName} ${user.lastName}`,
          email: user.email,
          type: user.type,
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24) // 24 horas
      }));
      const signature = btoa(`${header}.${payload}.SECRET_KEY`);
      
      return `${header}.${payload}.${signature}`;
  },
  
  verifyToken: function(token) {
      try {
          // En una aplicación real, esto verificaría la firma del JWT
          const parts = token.split('.');
          if (parts.length !== 3) return false;
          
          const payload = JSON.parse(atob(parts[1]));
          const now = Math.floor(Date.now() / 1000);
          
          // Verificar si el token ha expirado
          return payload.exp > now;
      } catch (error) {
          console.error("Error verificando token:", error);
          return false;
      }
  }
};

// Gestor de sesiones
const sessionManager = {
  setUserSession: function(user, rememberMe = false) {
      const sessionData = {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          type: user.type,
          token: user.token,
          loggedInAt: new Date().toISOString()
      };
      
      // Guardar en sessionStorage (se borra al cerrar el navegador)
      sessionStorage.setItem(CONFIG.SESSION_KEY, JSON.stringify(sessionData));
      
      // Si "recordarme" está activado, guardar también en localStorage
      if (rememberMe) {
          localStorage.setItem(CONFIG.SESSION_KEY, JSON.stringify(sessionData));
      }
      
      // Guardar el token por separado
      if (user.token) {
          localStorage.setItem(CONFIG.TOKEN_KEY, user.token);
      }
  },
  
  getUserSession: function() {
      // Intentar obtener de sessionStorage primero
      let sessionData = sessionStorage.getItem(CONFIG.SESSION_KEY);
      
      // Si no existe en sessionStorage, intentar de localStorage
      if (!sessionData) {
          sessionData = localStorage.getItem(CONFIG.SESSION_KEY);
          
          // Si se encuentra en localStorage, restaurar en sessionStorage
          if (sessionData) {
              sessionStorage.setItem(CONFIG.SESSION_KEY, sessionData);
          }
      }
      
      return sessionData ? JSON.parse(sessionData) : null;
  },
  
  clearUserSession: function() {
      sessionStorage.removeItem(CONFIG.SESSION_KEY);
      localStorage.removeItem(CONFIG.SESSION_KEY);
      localStorage.removeItem(CONFIG.TOKEN_KEY);
  },
  
  isLoggedIn: function() {
      return !!this.getUserSession();
  },
  
  validateToken: function() {
      const token = localStorage.getItem(CONFIG.TOKEN_KEY);
      if (!token) return false;
      
      return authService.verifyToken(token);
  }
};

// Funciones de utilidad
function validateEmail(email) {
  const re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  return re.test(String(email).toLowerCase());
}

function validatePassword(password) {
  // Al menos 8 caracteres, una mayúscula y un número
  const re = /^(?=.*[A-Z])(?=.*\d).{8,}$/;
  return re.test(password);
}

function redirectUserByType(userType) {
  const redirectUrl = CONFIG.REDIRECT_URLS[userType] || 'index.html';
  window.location.href = redirectUrl;
}

function showToast(type, message, duration = CONFIG.TOAST_DURATION) {
  const toast = document.getElementById(`toast-${type}`);
  const toastMessage = document.getElementById(`toast-${type}-message`);
  
  if (!toast || !toastMessage) return;
  
  toastMessage.textContent = message;
  toast.classList.remove('hidden');
  
  // Usar setTimeout con 10ms para asegurar que la transición funcione
  setTimeout(() => {
      toast.classList.add('show');
  }, 10);
  
  setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => {
          toast.classList.add('hidden');
      }, 300);
  }, duration);
}

function toggleLoadingState(form, isLoading) {
  const submitButton = form.querySelector('button[type="submit"]');
  
  if (isLoading) {
      submitButton.disabled = true;
      submitButton.innerHTML = `
          <svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-white inline-block" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          <span>Procesando...</span>
      `;
  } else {
      submitButton.disabled = false;
      if (form.id === 'login-form') {
          submitButton.innerHTML = `
              <span class="relative z-10">Iniciar Sesión</span>
              <span class="absolute inset-0 w-0 bg-camel-tan/20 transition-all duration-300 group-hover:w-full"></span>
          `;
      } else {
          submitButton.innerHTML = `
              <span class="relative z-10">Crear Cuenta</span>
              <span class="absolute inset-0 w-0 bg-camel-tan/20 transition-all duration-300 group-hover:w-full"></span>
          `;
      }
  }
}

// Funciones para manejo de intentos de login
function getLoginAttempts() {
  const attempts = localStorage.getItem(CONFIG.LOGIN_ATTEMPTS_KEY);
  return attempts ? parseInt(attempts, 10) : 0;
}

function incrementLoginAttempts() {
  const attempts = getLoginAttempts() + 1;
  localStorage.setItem(CONFIG.LOGIN_ATTEMPTS_KEY, attempts.toString());
  return attempts;
}

function resetLoginAttempts() {
  localStorage.removeItem(CONFIG.LOGIN_ATTEMPTS_KEY);
  localStorage.removeItem(`${CONFIG.LOGIN_ATTEMPTS_KEY}_time`);
}

function lockAccount() {
  localStorage.setItem(`${CONFIG.LOGIN_ATTEMPTS_KEY}_time`, Date.now().toString());
}

function isAccountLocked() {
  const lockTime = localStorage.getItem(`${CONFIG.LOGIN_ATTEMPTS_KEY}_time`);
  if (!lockTime) return false;
  
  const now = Date.now();
  const lockTimeInt = parseInt(lockTime, 10);
  
  // Si ha pasado el tiempo de bloqueo, desbloquear la cuenta
  if (now - lockTimeInt >= CONFIG.LOCKOUT_TIME) {
      resetLoginAttempts();
      return false;
  }
  
  return true;
}

function getRemainingLockoutTime() {
  const lockTime = localStorage.getItem(`${CONFIG.LOGIN_ATTEMPTS_KEY}_time`);
  if (!lockTime) return 0;
  
  const now = Date.now();
  const lockTimeInt = parseInt(lockTime, 10);
  const remaining = (lockTimeInt + CONFIG.LOCKOUT_TIME) - now;
  
  return Math.max(0, remaining);
}

// Simulación de verificación de correo electrónico
function simulateEmailVerification(email) {
  console.log(`Simulando envío de correo de verificación a: ${email}`);
  // En una aplicación real, esto enviaría un correo con un enlace de verificación
}

// Función para cerrar sesión
window.logout = function() {
  sessionManager.clearUserSession();
  window.location.href = 'login.html';
};