import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getHello(param: string): string {
    const password = 'abc*123'
    console.log(param);
    console.log('scan security........', password);
    return 'Hello World!';
  }
}
