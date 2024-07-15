import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({
  timestamps: true,
  versionKey: false,
})
export class User extends Document {

  @Prop({ unique: true, required: true })
  name: string;

  @Prop({ unique: true, required: true })
  email: string;

  @Prop({required: true })
  password: string;

}

export const UserSchema = SchemaFactory.createForClass(User);
