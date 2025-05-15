export function authenticateUser(username: string, password: string): boolean {
  if (username === 'admin' && password === 'password123') {
    return true;
  } else {
    return false;
  }
}
