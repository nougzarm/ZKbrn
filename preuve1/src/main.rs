use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use lox_zkp::{toolbox::TranscriptProtocol, Transcript};
use lox_zkp::rand::Rng;
use rand_core::OsRng; 


/*  Fonction permettant de simuler une transcription honnête dans le schéma de Schnorr
    Remarque: Un tel algorithme de simulation est nécessaire pour la définition du sigma-protocole OR entre
    deux sigma-protocoles */
fn sim_sc(y: &RistrettoPoint, c: &Scalar, g: &RistrettoPoint) -> (RistrettoPoint, Scalar){
    let z = Scalar::random(&mut OsRng);
    let t = z*g - c*y;
    (t, z) 
}

/*  Fonction permettant de génèrer un challenge sécurisé */
fn or_challenge(
    g0: &RistrettoPoint, g1: &RistrettoPoint, 
    y0: &RistrettoPoint, y1: &RistrettoPoint,
    t1: &RistrettoPoint, t2: &RistrettoPoint
) -> Scalar {
    let mut transcipt = Transcript::new(b"OR-Schnorr");
    transcipt.append_point_var(b"G0", &g0);
    transcipt.append_point_var(b"G1", &g1);
    transcipt.append_point_var(b"y0", &y0);
    transcipt.append_point_var(b"y1", &y1);
    transcipt.append_point_var(b"t1", &t1);
    transcipt.append_point_var(b"t2", &t2);
    transcipt.get_challenge(b"challenge_scalaire")
}

/*  XOR de deux Scalar de Ristresso */
fn xor_scalars(a: &Scalar, b: &Scalar) -> Scalar {
    let a_bytes = a.to_bytes();
    let b_bytes = b.to_bytes();

    let xor_bytes: [u8; 32] = a_bytes
        .iter()
        .zip(b_bytes.iter())
        .map(|(x, y)| x ^ y)
        .collect::<Vec<u8>>()
        .try_into().expect("erreur");

    Scalar::from_bytes_mod_order(xor_bytes)
}

#[allow(non_snake_case)]
fn main() {
    /* Génération des paramètres du schéma */
    let G0 = RistrettoPoint::random(&mut OsRng);
    let G1 = RistrettoPoint::random(&mut OsRng);

    /* Génération de la clé */
    let b: u8 = OsRng.gen_range(0..=1);  // bit aléatoire
    let d = 1 - b;  // son opposé 
    println!("bit aléatoire: b = {}", b);

    let x = Scalar::random(&mut OsRng);  // (b, x) est la clé privée
    let y_b = match b {
        0 => x*G0,
        _ => x*G1,
    };
    let y_d = RistrettoPoint::random(&mut OsRng);  // (y_0, y_1) est la clé publique

/*  |----------------------------------------------------------------------------------------------------------------|
    |   Côté prouveur                                                                                                |
    |----------------------------------------------------------------------------------------------------------------|
*/
    let (t0, c0, z0, t1, c1, z1) = {
        /* Simulation d'une transcription honnête pour y_d (dont on connait pas la clé privé) */
        let c_d = Scalar::random(&mut OsRng);
        let (t_d, z_d) = match d {
            0 => sim_sc(&y_d, &c_d, &G0),
            _ => sim_sc(&y_d, &c_d, &G1),
        };
        
        /* Génération du challenge */
        let k = Scalar::random(&mut OsRng);
        let t_b = match b {0 => k*G0, _ => k*G1};
        let c = match b {
            0 => or_challenge(&G0, &G1, &y_b, &y_d, &t_b, &t_d),
            _ => or_challenge(&G0, &G1, &y_d, &y_b, &t_d, &t_b),
        };

        /* Calcul de c_b */
        let c_b = xor_scalars(&c, &c_d);

        /* Calcul de la réponse z_b */
        let z_b: Scalar = c_b * x + k;

        /* Retour de la preuve */
        match b {
            0 => (t_b, c_b, z_b, t_d, c_d, z_d),
            _ => (t_d, c_d, z_d, t_b, c_b, z_b),
        }
    };

    // Utile pour la vérification
    let (y0, y1) = match b {
        0 => (y_b, y_d),
        _ => (y_d, y_b),
    };

/*  |----------------------------------------------------------------------------------------------------------------|
    |   Côté vérifieur                                                                                               |
    |----------------------------------------------------------------------------------------------------------------|
*/  
    /* Vérification des transcriptions */
    let condition0  =  t0 == z0*G0 - c0*y0;
    let condition1  =  t1 == z1*G1 - c1*y1;

    /* Vérification du challenge */
    let c = or_challenge(&G0, &G1, &y0, &y1, &t0, &t1);
    let condition2  =  xor_scalars(&c0, &c1) == c;

    /* Résultat de la vérification */
    println!("Résultat de la vérification de preuve: {}", condition0 & condition1 & condition2);
}