import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { sanitizeInput } from './common/utils/sanitize.utils';

/**
 * Service for handling user data operations
 */
@Injectable()
export class UserDataService {
  private readonly logger = new Logger(UserDataService.name);
  private readonly uploadDir: string;

  constructor(private readonly configService: ConfigService) {
    this.uploadDir = this.configService.get<string>('UPLOAD_DIRECTORY', './uploads');
    // Ensure upload directory exists
    if (!fs.existsSync(this.uploadDir)) {
      fs.mkdirSync(this.uploadDir, { recursive: true });
    }
  }

  /**
   * Process user data safely with proper validation
   * @param userData - User data object containing user information
   * @returns Object with success status and processed data
   */
  async processUserData(userData: { id: string; address?: string }): Promise<{ success: boolean; data?: unknown }> {
    try {
      // Validate input
      if (!userData || !userData.id) {
        return { success: false, data: 'Invalid user data provided' };
      }

      // Sanitize inputs to prevent injection
      const sanitizedId = sanitizeInput(userData.id);
      
      // Use parameterized queries instead of string concatenation
      const result = await this.executeQuery('SELECT * FROM users WHERE id = ?', [sanitizedId]);
      
      // Return only necessary data, avoid leaking internal information
      return { 
        success: true, 
        data: result 
      };
    } catch (error) {
      // Log the full error but return limited info to client
      this.logger.error(`Error processing user data: ${error.message}`, error.stack);
      return { success: false, data: 'An error occurred while processing user data' };
    }
  }

  /**
   * Handle file uploads securely
   * @param filename - Name of the file to be saved
   * @param content - Content of the file
   * @returns Promise with the result of the operation
   */
  async handleFileUpload(filename: string, content: string): Promise<string> {
    try {
      // Validate filename
      if (!filename || typeof filename !== 'string') {
        throw new Error('Invalid filename provided');
      }

      // Sanitize filename to prevent path traversal
      const sanitizedFilename = path.basename(filename);
      
      // Generate a unique filename to prevent overwriting
      const uniqueFilename = `${Date.now()}-${sanitizedFilename}`;
      
      // Use async file operations to avoid blocking the event loop
      const writeFileAsync = promisify(fs.writeFile);
      const filePath = path.join(this.uploadDir, uniqueFilename);
      
      await writeFileAsync(filePath, content);
      
      // Return a success message without exposing the full path
      return `File uploaded successfully with ID: ${uniqueFilename}`;
    } catch (error) {
      this.logger.error(`Error handling file upload: ${error.message}`, error.stack);
      throw new Error('Failed to upload file');
    }
  }

  /**
   * Execute database query safely with parameterized queries
   * @param query - SQL query with placeholders
   * @param params - Parameters to be used in the query
   * @returns Promise with query results
   * @private
   */
  private async executeQuery(query: string, params: unknown[]): Promise<unknown> {
    // This is a placeholder for actual database query execution
    // In a real application, you would use your database client here
    this.logger.debug(`Executing query: ${query} with params: ${JSON.stringify(params)}`);
    return { id: params[0], name: 'Sample User' };
  }
}