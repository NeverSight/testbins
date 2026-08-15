with Ada.Command_Line;
with Ada.Text_IO;

procedure Ada_EH_Probe is
   Decode_Error    : exception;
   Secondary_Error : exception;
   Cleanup_Count   : Natural := 0;

   function Parse_Selector return Integer is
   begin
      if Ada.Command_Line.Argument_Count = 0 then
         return 3;
      end if;
      return Integer'Value (Ada.Command_Line.Argument (1));
   exception
      when Constraint_Error =>
         return 0;
   end Parse_Selector;

   function May_Raise (Selector : Integer) return Integer is
   begin
      case Selector is
         when 0 =>
            raise Constraint_Error with "constraint";
         when 1 =>
            raise Decode_Error with "decode";
         when 2 =>
            raise Secondary_Error with "secondary";
         when others =>
            return 40 + Selector;
      end case;
   end May_Raise;

   Selector : constant Integer := Parse_Selector;
   Result   : Integer := 0;
begin
   begin
      Result := May_Raise (Selector);
   exception
      when Constraint_Error =>
         Result := 10;
      when Decode_Error =>
         Result := 20;
      when Secondary_Error =>
         Result := 30;
      when others =>
         Result := 90;
   end;

   Cleanup_Count := Cleanup_Count + 1;
   if Result + Integer (Cleanup_Count) = 44 then
      Ada.Text_IO.Put_Line ("ada-d-eh probe passed");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Success);
   else
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Ada_EH_Probe;
