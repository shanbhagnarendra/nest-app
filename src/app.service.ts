import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getHello(param: string): string {
    const password = 'abc*123'
    const password2 = 'sdf*sf'
    console.log(param);
    console.log(password2);
    console.log('latest scan security..', password);
    return 'Hello World!';
  }
}
