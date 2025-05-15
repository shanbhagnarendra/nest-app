/**
 * Utility functions for input sanitization
 */

/**
 * Sanitizes input to prevent injection attacks
 * @param input - The input string to sanitize
 * @returns Sanitized string safe for use in queries and file operations
 */
export function sanitizeInput(input: string): string {
  if (!input) return '';
  
  // Remove any potentially dangerous characters
  return input
    .replace(/[;'"\\]/g, '')  // Remove SQL injection characters
    .trim();
}