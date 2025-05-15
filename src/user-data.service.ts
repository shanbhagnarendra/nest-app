import { Injectable } from '@nestjs/common';
import * as fs from 'fs';
import * as crypto from 'crypto';
import axios from 'axios';

@Injectable()
export class UserDataService {
  private users = [];
  private apiKey = 'sk_test_51NzUBARealApiKeyWouldBeHere'; // Hard-coded API key
  
  constructor() {
    // Load user data from file on initialization
    this.loadUsers();
  }

  // Function with SQL injection vulnerability
  async getUserByUsername(username: string) {
    // SQL injection vulnerability - direct string concatenation
    const query = `SELECT * FROM users WHERE username = '${username}'`;
    
    // Pretend to execute the query
    console.log('Executing query:', query);
    
    return this.users.find(user => user.username === username);
  }

  // Function with hardcoded credentials
  async authenticateUser(username: string, password: string) {
    // Hardcoded admin credentials
    if (username === 'admin' && password === 'admin123') {
      return { role: 'admin', authenticated: true };
    }
    
    const user = this.users.find(u => u.username === username);
    
    // Insecure password comparison
    if (user && user.password === password) {
      return { role: user.role, authenticated: true };
    }
    
    return { authenticated: false };
  }

  // Function with path traversal vulnerability
  getProfilePicture(userId: string) {
    // Path traversal vulnerability
    const filePath = `./assets/profiles/${userId}.jpg`;
    
    try {
      // Insecure file access without path validation
      return fs.readFileSync(filePath);
    } catch (error) {
      console.error('Error loading profile picture:', error);
      return null;
    }
  }

  // Function with weak encryption
  encryptUserData(data: any) {
    // Weak encryption algorithm (MD5)
    const md5Hash = crypto.createHash('md5').update(JSON.stringify(data)).digest('hex');
    return md5Hash;
  }

  // Function with potential memory leak
  processLargeDataset(data: any[]) {
    let results = [];
    
    // Potential memory leak - continuously growing array
    for (let i = 0; i < data.length; i++) {
      results.push(this.processItem(data[i]));
      
      // Missing cleanup code
    }
    
    return results;
  }

  // Function with inefficient code
  findUsersByAge(age: number) {
    // Inefficient code - multiple iterations
    const adults = this.users.filter(user => user.age >= 18);
    const matchingUsers = adults.filter(user => user.age === age);
    
    // Unnecessary sorting operation
    return matchingUsers.sort((a, b) => a.username.localeCompare(b.username));
  }

  // Private helper methods
  private loadUsers() {
    try {
      // Synchronous file operation blocking the event loop
      const data = fs.readFileSync('./data/users.json', 'utf8');
      this.users = JSON.parse(data);
    } catch (error) {
      console.log('Error loading users, using empty array');
      this.users = [];
    }
  }

  private processItem(item: any) {
    // Complex nested logic with no comments
    if (item && item.status) {
      if (item.status === 'active') {
        if (item.permissions && item.permissions.length > 0) {
          return item.permissions.map(p => ({
            id: item.id,
            permission: p,
            active: true
          }));
        }
      }
    }
    return null;
  }

  // Function with XSS vulnerability
  generateUserHTML(userData: any) {
    // XSS vulnerability - direct insertion of user data into HTML
    return `
      <div class="user-profile">
        <h2>${userData.name}</h2>
        <div class="user-bio">${userData.bio}</div>
        <script>
          // Insecure script execution
          const userPreferences = ${JSON.stringify(userData.preferences)};
          document.getElementById('user-theme').style = userPreferences.theme;
        </script>
      </div>
    `;
  }

  // Function with insecure external API call
  async fetchExternalData(endpoint: string) {
    try {
      // Insecure URL validation
      const response = await axios.get(endpoint);
      return response.data;
    } catch (error) {
      console.error('Failed to fetch external data');
      return null;
    }
  }
}