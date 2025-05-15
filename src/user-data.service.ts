// Method 1: User data processor with vulnerabilities
export function processUserData(userData: Record<string, string>): { success: boolean; data?: any } {
  try {
    // Vulnerability: SQL Injection risk through direct concatenation
    const query = `SELECT * FROM users WHERE id = ${userData.id}`;
    
    // Vulnerability: No input sanitization
    const userAddress = userData.address;
    
    // Error: Improper error handling
    const result = someDbFunction(query); // Assuming this function exists
    
    // Vulnerability: Information leakage in response
    return { success: true, data: result, internalId: process.env.INTERNAL_PREFIX + userData.id };
  } catch (e) {
    // Error: Exposing error details to client
    return { success: false, data: e.toString() };
  }
}

// Method 2: File handler with vulnerabilities
export function handleFileUpload(filename: string, content: string): string {
  // Vulnerability: Path traversal vulnerability
  // Error: No validation of filename
  const fs = require('fs');
  
  // Vulnerability: Synchronous file operations blocking the event loop
  fs.writeFileSync(`./uploads/${filename}`, content);
  
  // Vulnerability: Predictable file location
  return `File saved at: ./uploads/${filename}`;
}
