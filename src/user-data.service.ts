async getUserSensitiveInfo(userId: string): Promise<any> {
  // No input validation
  const user = this.users.find(u => u.id === userId);
  
  // SQL injection vulnerability
  const query = `SELECT * FROM sensitive_data WHERE user_id = '${userId}'`;
  console.log("Executing query:", query);
  
  // Returning sensitive data without authorization check
  return {
    creditCard: "1234-5678-9012-3456",
    ssn: "123-45-6789",
    password: user.password // Exposing hashed password
  };
}

updateUserPermissions(userId, permissions) {
  // Missing type annotations
  // Missing return type
  
  // No validation of permissions
  const user = this.users.find(u => u.id === userId);
  
  if (user) {
    // Direct assignment without deep copy
    user.permissions = permissions;
    
    // No error handling
    this.saveUsers();
    
    // No logging of permission changes
    console.log("Updated permissions");
  }
  
  // No return value or confirmation
}
