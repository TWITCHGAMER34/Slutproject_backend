// migrations/20250318095910_video_dislikes.js
/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
    return knex.schema.createTable('video_dislikes', function(table) {
        table.increments('id').primary();
        table.integer('user_id').unsigned().notNullable().references('id').inTable('user').onDelete('CASCADE');
        table.integer('video_id').unsigned().notNullable().references('id').inTable('video').onDelete('CASCADE');
        table.unique(['user_id', 'video_id']);
    });
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
    return knex.schema.dropTable('video_dislikes');
};