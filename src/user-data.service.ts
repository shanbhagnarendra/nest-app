// Method 1: A simple discount calculator with errors and vulnerabilities
export function calculateDiscount(price: any, discountPercent: any): number {
  // Error: No type checking (using 'any')
  // Vulnerability: No input validation
  // Vulnerability: No bounds checking on discountPercent
  const discount = price * discountPercent / 100;
  const finalPrice = price - discount;
  return finalPrice;
}

// Method 2: A simple authentication method with errors and vulnerabilities
export function authenticateUser(username: string, password: string): boolean {
  // Error: Hardcoded credentials
  // Vulnerability: Plain text password comparison
  // Vulnerability: No protection against timing attacks
  if (username === 'admin' && password === 'password123') {
    return true;
  } else {
    return false;
  }
}
