import { Injectable, BadRequestException, UnauthorizedException, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';

/**
 * Interface for authentication result
 */
interface IAuthResult {
  authenticated: boolean;
  userId?: string;
  role?: string;
}

/**
 * Interface for user credentials
 */
interface IUserCredentials {
  username: string;
  passwordHash: string;
  salt: string;
  userId: string;
  role: string;
}

/**
 * Service for handling user authentication
 */
@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly users: Map<string, IUserCredentials> = new Map();

  constructor(private readonly configService: ConfigService) {
    // Load user credentials from secure storage in a real application
    this.loadUserCredentials();
  }

  /**
   * Authenticates a user with username and password
   * @param username - The username to authenticate
   * @param password - The password to verify
   * @returns Authentication result with user information
   * @throws BadRequestException if inputs are invalid
   * @throws UnauthorizedException if authentication fails
   */
  async authenticateUser(username: string, password: string): Promise<IAuthResult> {
    try {
      // Input validation
      if (!username || typeof username !== 'string') {
        throw new BadRequestException('Username must be a non-empty string');
      }

      if (!password || typeof password !== 'string') {
        throw new BadRequestException('Password must be a non-empty string');
      }

      // Find user credentials
      const userCredentials = this.users.get(username);
      if (!userCredentials) {
        // Use constant time comparison even for non-existent users to prevent timing attacks
        await this.comparePasswordConstantTime(password, 'dummy-hash', 'dummy-salt');
        throw new UnauthorizedException('Invalid credentials');
      }

      // Verify password with constant-time comparison
      const isPasswordValid = await this.comparePasswordConstantTime(
        password,
        userCredentials.passwordHash,
        userCredentials.salt
      );

      if (!isPasswordValid) {
        throw new UnauthorizedException('Invalid credentials');
      }

      return {
        authenticated: true,
        userId: userCredentials.userId,
        role: userCredentials.role
      };
    } catch (error) {
      // Log error but don't expose details to client
      this.logger.error(`Authentication error: ${error.message}`);
      
      // Re-throw specific exceptions
      if (error instanceof BadRequestException || error instanceof UnauthorizedException) {
        throw error;
      }
      
      // Generic error for anything else
      throw new UnauthorizedException('Authentication failed');
    }
  }

  /**
   * Registers a new user with secure password hashing
   * @param username - The username to register
   * @param password - The password to hash and store
   * @returns User ID of the newly registered user
   * @throws BadRequestException if inputs are invalid or user already exists
   */
  async registerUser(username: string, password: string): Promise<string> {
    try {
      // Input validation
      if (!username || typeof username !== 'string') {
        throw new BadRequestException('Username must be a non-empty string');
      }

      if (!password || typeof password !== 'string' || password.length < 8) {
        throw new BadRequestException('Password must be at least 8 characters long');
      }

      // Check if user already exists
      if (this.users.has(username)) {
        throw new BadRequestException('Username already exists');
      }

      // Generate salt and hash password
      const salt = crypto.randomBytes(16).toString('hex');
      const passwordHash = await this.hashPassword(password, salt);
      const userId = crypto.randomUUID();

      // Store user credentials
      this.users.set(username, {
        username,
        passwordHash,
        salt,
        userId,
        role: 'user'
      });

      // Save user credentials to secure storage in a real application
      await this.saveUserCredentials();

      return userId;
    } catch (error) {
      this.logger.error(`Registration error: ${error.message}`);
      
      if (error instanceof BadRequestException) {
        throw error;
      }
      
      throw new BadRequestException('User registration failed');
    }
  }

  /**
   * Hashes a password with a salt using a secure algorithm
   * @param password - The password to hash
   * @param salt - The salt to use for hashing
   * @returns Promise resolving to the hashed password
   * @private
   */
  private async hashPassword(password: string, salt: string): Promise<string> {
    return new Promise((resolve, reject) => {
      // Use PBKDF2 with SHA-512 and 10000 iterations for secure hashing
      crypto.pbkdf2(password, salt, 10000, 64, 'sha512', (err, derivedKey) => {
        if (err) {
          reject(err);
        } else {
          resolve(derivedKey.toString('hex'));
        }
      });
    });
  }

  /**
   * Compares a password with a hash using constant-time comparison
   * @param password - The password to verify
   * @param hash - The stored password hash
   * @param salt - The salt used for hashing
   * @returns Promise resolving to whether the password is valid
   * @private
   */
  private async comparePasswordConstantTime(password: string, hash: string, salt: string): Promise<boolean> {
    try {
      const inputHash = await this.hashPassword(password, salt);
      
      // Use crypto.timingSafeEqual for constant-time comparison to prevent timing attacks
      return crypto.timingSafeEqual(
        Buffer.from(inputHash, 'hex'),
        Buffer.from(hash, 'hex')
      );
    } catch (error) {
      this.logger.error('Password comparison failed', error);
      return false;
    }
  }

  /**
   * Loads user credentials from secure storage
   * @private
   */
  private loadUserCredentials(): void {
    try {
      // In a real application, load from database or secure storage
      // For demo purposes, we'll add a test user with properly hashed password
      const testSalt = crypto.randomBytes(16).toString('hex');
      
      // Pre-compute hash for demo user (in real app, this would be stored securely)
      crypto.pbkdf2('securePassword123', testSalt, 10000, 64, 'sha512', (err, derivedKey) => {
        if (err) {
          this.logger.error('Failed to create test user');
          return;
        }
        
        this.users.set('testuser', {
          username: 'testuser',
          passwordHash: derivedKey.toString('hex'),
          salt: testSalt,
          userId: 'test-user-id',
          role: 'user'
        });
      });
    } catch (error) {
      this.logger.error('Failed to load user credentials', error);
    }
  }

  /**
   * Saves user credentials to secure storage
   * @private
   */
  private async saveUserCredentials(): Promise<void> {
    // In a real application, save to database or secure storage
    this.logger.log('User credentials updated');
  }
}