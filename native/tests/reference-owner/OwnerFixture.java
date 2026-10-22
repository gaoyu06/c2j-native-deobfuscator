package fixture;
public class OwnerFixture {
 public static Class<?> resolve(String ignored) { return ActualOwner.class; }
 public static native int run();
 public static void main(String[] args) { System.load(args[0]); if(run()!=43)throw new AssertionError(); System.out.println("OWNER_FIXTURE_OK"); }
}
class ActualOwner { public static int field=7; public static int x(int a,int b){return a^b;} }
