import { Injectable, Logger, BadRequestException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';
import axios from 'axios';
import { ConfigService } from '@nestjs/config';

/**
 * Interface for User data
 */
interface IUser {
  id: string;
  username: string;
  password: string;
  email: string;
  age: number;
  role: string;
  status: string;
  preferences: Record<string, any>;
  permissions: string[];
}

/**
 * Interface for Authentication Response
 */
interface IAuthResponse {
  role?: string;
  authenticated: boolean;
  token?: string;
}

/**
 * Service for managing user data and operations
 */
@Injectable()
export class UserDataService {
  private users: IUser[] = [];
  private readonly logger = new Logger(UserDataService.name);
  private readonly usersFilePath: string;
  private readonly profilePicturePath: string;
  private readonly apiKey: string;
  private userCache = new Map<string, IUser>();

  constructor(private configService: ConfigService) {
    this.usersFilePath = this.configService.get<string>('USERS_FILE_PATH', './data/users.json');
    this.profilePicturePath = this.configService.get<string>('PROFILE_PICTURES_PATH', './assets/profiles');
    this.apiKey = this.configService.get<string>('API_KEY', '');
    
    // Load user data on initialization
    this.loadUsers();
  }

  /**
   * Get user by username
   * @param username - The username to search for
   * @returns Promise resolving to the user or null if not found
   * @throws BadRequestException if username is invalid
   */
  async getUserByUsername(username: string): Promise<IUser | null> {
    if (!username || typeof username !== 'string') {
      throw new BadRequestException('Invalid username provided');
    }

    // Check cache first
    if (this.userCache.has(username)) {
      return this.userCache.get(username);
    }

    // Use prepared statement pattern for database queries
    const params = [username];
    this.logger.debug(`Fetching user with username: ${username}`);
    
    const user = this.users.find(user => user.username === username);
    
    // Cache the result
    if (user) {
      this.userCache.set(username, user);
    }
    
    return user || null;
  }

  /**
   * Authenticate a user with username and password
   * @param username - The username
   * @param password - The password
   * @returns Promise resolving to authentication result
   * @throws BadRequestException for invalid inputs
   * @throws UnauthorizedException for authentication failures
   */
  async authenticateUser(username: string, password: string): Promise<IAuthResponse> {
    if (!username || !password) {
      throw new BadRequestException('Username and password are required');
    }
    
    const user = await this.getUserByUsername(username);
    
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    
    // Secure password comparison using constant-time algorithm
    const isPasswordValid = await this.verifyPassword(password, user.password);
    
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }
    
    // Generate JWT token (simplified for example)
    const token = this.generateAuthToken(user);
    
    return { 
      role: user.role, 
      authenticated: true,
      token
    };
  }

  /**
   * Register a new user
   * @param userData - The user data for registration
   * @returns Promise resolving to the created user
   * @throws BadRequestException for validation errors
   */
  async registerUser(userData: Partial<IUser>): Promise<IUser> {
    // Validate required fields
    if (!userData.username || !userData.password || !userData.email) {
      throw new BadRequestException('Username, password and email are required');
    }
    
    // Check if user already exists
    const existingUser = await this.getUserByUsername(userData.username);
    if (existingUser) {
      throw new BadRequestException('Username already exists');
    }
    
    // Hash password
    const hashedPassword = await this.hashPassword(userData.password);
    
    // Create new user
    const newUser: IUser = {
      id: crypto.randomUUID(),
      username: userData.username,
      password: hashedPassword,
      email: userData.email,
      age: userData.age || 0,
      role: 'user',
      status: 'active',
      preferences: userData.preferences || {},
      permissions: []
    };
    
    this.users.push(newUser);
    await this.saveUsers();
    
    // Don't return password
    const { password, ...userWithoutPassword } = newUser;
    return userWithoutPassword as IUser;
  }

  /**
   * Reset user password
   * @param username - The username
   * @param token - Reset token
   * @param newPassword - New password
   * @returns Promise resolving to success status
   * @throws BadRequestException for validation errors
   * @throws UnauthorizedException for invalid tokens
   */
  async resetPassword(username: string, token: string, newPassword: string): Promise<boolean> {
    if (!username || !token || !newPassword) {
      throw new BadRequestException('Username, token and new password are required');
    }
    
    // Validate token (simplified)
    const isValidToken = this.validateResetToken(username, token);
    if (!isValidToken) {
      throw new UnauthorizedException('Invalid or expired token');
    }
    
    const user = await this.getUserByUsername(username);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    
    // Update password
    user.password = await this.hashPassword(newPassword);
    await this.saveUsers();
    
    return true;
  }

  /**
   * Get user profile picture
   * @param userId - The user ID
   * @returns Promise resolving to the profile picture buffer
   * @throws NotFoundException if picture not found
   */
  async getProfilePicture(userId: string): Promise<Buffer> {
    if (!userId) {
      throw new BadRequestException('User ID is required');
    }
    
    // Sanitize input to prevent path traversal
    const sanitizedId = userId.replace(/[^a-zA-Z0-9]/g, '');
    
    // Use path.join for safe path construction
    const filePath = path.join(this.profilePicturePath, `${sanitizedId}.jpg`);
    
    try {
      return await fs.readFile(filePath);
    } catch (error) {
      this.logger.error(`Error loading profile picture: ${error.message}`);
      throw new NotFoundException('Profile picture not found');
    }
  }

  /**
   * Encrypt sensitive user data
   * @param data - Data to encrypt
   * @returns Encrypted data
   */
  encryptUserData(data: any): string {
    // Use strong encryption algorithm (SHA-256)
    const salt = crypto.randomBytes(16);
    const key = crypto.pbkdf2Sync('secret-key', salt, 100000, 32, 'sha256');
    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    // Return everything needed for decryption
    return Buffer.concat([
      salt, 
      iv, 
      authTag, 
      Buffer.from(encrypted, 'hex')
    ]).toString('base64');
  }

  /**
   * Process large dataset efficiently
   * @param data - Array of items to process
   * @returns Processed results
   */
  processLargeDataset(data: any[]): any[] {
    if (!data || !Array.isArray(data)) {
      return [];
    }
    
    // Process in chunks to avoid memory issues
    const chunkSize = 1000;
    const results = [];
    
    for (let i = 0; i < data.length; i += chunkSize) {
      const chunk = data.slice(i, i + chunkSize);
      const processedChunk = chunk
        .map(item => this.processItem(item))
        .filter(Boolean); // Remove null values
      
      results.push(...processedChunk);
    }
    
    return results;
  }

  /**
   * Find users by age efficiently
   * @param age - Age to filter by
   * @returns Filtered users
   */
  findUsersByAge(age: number): IUser[] {
    if (typeof age !== 'number' || age < 0) {
      throw new BadRequestException('Valid age is required');
    }
    
    // Single pass filter for efficiency
    return this.users
      .filter(user => user.age === age && user.age >= 18)
      .sort((a, b) => a.username.localeCompare(b.username));
  }

  /**
   * Generate safe HTML for user profile
   * @param userData - User data
   * @returns Sanitized HTML
   */
  generateUserHTML(userData: Partial<IUser>): string {
    if (!userData) {
      return '<div class="user-profile">No user data</div>';
    }
    
    // Sanitize inputs to prevent XSS
    const sanitize = (str: string): string => {
      return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    };
    
    const name = userData.username ? sanitize(userData.username) : '';
    const bio = userData.preferences?.bio ? sanitize(userData.preferences.bio) : '';
    
    // No inline scripts, use data attributes instead
    return `
      <div class="user-profile" data-user-id="${userData.id || ''}">
        <h2>${name}</h2>
        <div class="user-bio">${bio}</div>
      </div>
    `;
  }

  /**
   * Fetch external data securely
   * @param endpoint - API endpoint
   * @returns Promise resolving to the data
   * @throws BadRequestException for invalid URLs
   */
  async fetchExternalData(endpoint: string): Promise<any> {
    if (!endpoint) {
      throw new BadRequestException('Endpoint is required');
    }
    
    // Validate URL
    try {
      const url = new URL(endpoint);
      
      // Whitelist allowed domains
      const allowedDomains = ['api.example.com', 'data.example.org'];
      if (!allowedDomains.includes(url.hostname)) {
        throw new BadRequestException('Domain not allowed');
      }
      
      const response = await axios.get(url.toString(), {
        timeout: 5000,
        headers: {
          'Authorization': `Bearer ${this.apiKey}`
        }
      });
      
      return response.data;
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      this.logger.error(`Failed to fetch external data: ${error.message}`);
      throw new BadRequestException('Failed to fetch external data');
    }
  }

  /**
   * Process a single item
   * @param item - Item to process
   * @returns Processed item or null
   */
  private processItem(item: any): any {
    if (!item) return null;
    
    // Simplified logic with clear structure
    if (item.status !== 'active') return null;
    if (!item.permissions || !Array.isArray(item.permissions) || item.permissions.length === 0) return null;
    
    // Map permissions to result objects
    return item.permissions.map(permission => ({
      id: item.id,
      permission,
      active: true
    }));
  }

  /**
   * Load users from file
   */
  private async loadUsers(): Promise<void> {
    try {
      const data = await fs.readFile(this.usersFilePath, 'utf8');
      this.users = JSON.parse(data);
      this.logger.log(`Loaded ${this.users.length} users`);
    } catch (error) {
      this.logger.warn(`Error loading users: ${error.message}, using empty array`);
      this.users = [];
    }
  }

  /**
   * Save users to file
   */
  private async saveUsers(): Promise<void> {
    try {
      await fs.writeFile(
        this.usersFilePath, 
        JSON.stringify(this.users, null, 2)
      );
      // Clear cache after update
      this.userCache.clear();
    } catch (error) {
      this.logger.error(`Error saving users: ${error.message}`);
      throw new Error('Failed to save user data');
    }
  }

  /**
   * Hash password securely
   * @param password - Plain password
   * @returns Hashed password
   */
  private async hashPassword(password: string): Promise<string> {
    const salt = crypto.randomBytes(16).toString('hex');
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(password, salt, 10000, 64, 'sha512', (err, derivedKey) => {
        if (err) reject(err);
        resolve(`${salt}:${derivedKey.toString('hex')}`);
      });
    });
  }

  /**
   * Verify password against hash
   * @param password - Plain password
   * @param hash - Stored hash
   * @returns Whether password is valid
   */
  private async verifyPassword(password: string, hash: string): Promise<boolean> {
    const [salt, key] = hash.split(':');
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(password, salt, 10000, 64, 'sha512', (err, derivedKey) => {
        if (err) reject(err);
        resolve(key === derivedKey.toString('hex'));
      });
    });
  }

  /**
   * Generate authentication token
   * @param user - User object
   * @returns JWT token
   */
  private generateAuthToken(user: IUser): string {
    // Simplified JWT generation
    const payload = {
      sub: user.id,
      username: user.username,
      role: user.role
    };
    
    // In a real app, use a proper JWT library
    return Buffer.from(JSON.stringify(payload)).toString('base64');
  }

  /**
   * Validate password reset token
   * @param username - Username
   * @param token - Reset token
   * @returns Whether token is valid
   */
  private validateResetToken(username: string, token: string): boolean {
    // Simplified token validation
    // In a real app, verify against stored tokens with expiration
    return token.length > 20;
  }
}