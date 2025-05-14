import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getHello(param: string): string {
    console.log(param);
    console.log('scan security', param);
    return 'Hello World!';
  }
}
